#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
csdev :: tools/sleeve_extract.py -- 把 CS 4.7 的 sleeve 资源还原成标准 COFF
==============================================================================
用途
    本项目需要真实 BOF 样本验证加载器 (kits/beacon/bof.c)。Cobalt Strike 4.7
    的 client jar 里 sleeve/ 目录下的 .o 既被加密、又去掉了 COFF 头的前 8 字节,
    无法直接喂给任何标准 COFF 工具。本脚本把它还原成 objdump/链接器都能识别的
    标准 pe-x86-64 目标文件。

只读约束
    输入一律只读打开; 输出写到 --out 指定目录, 不触碰任何 CS 发行物。

格式还原过程 (两段, 均已实测)
    1) sleeve 容器 (CS 4.7)
         [16B IV][AES-128-CBC 密文][16B HMAC-SHA256]
       - AES key  = SHA256(master)[0:16]
       - HMAC key = SHA256(master)[16:32], 覆盖范围 = IV || 密文
       - 明文尾部用 'A' (0x41) 补齐到 16 字节边界
       (对照: dns/SleeveSecurity.java 里 IV 是常量 b"abcdefghijklmnop"; 4.7
        实际发行物改用每文件随机 IV 前置, 以实测结果为准。)

    2) 内层 = 完整 COFF 去掉前 8 字节 (Machine 2 + NumberOfSections 2 +
       TimeDateStamp 4)。因此内层所有 PointerToRawData / PointerToSymbolTable
       仍相对"完整 COFF"计数, 重建时只需补回 20 字节头并把节表及其后内容
       整体后移 8 字节。

master key 来源
    cobaltstrike.auth 解密后取出的 sleeve key, 现有副本见
    D:\\cobalt_strike_4.7\\_recon\\sleeve_master.hex (32 个 hex 字符 = 16 字节)。
==============================================================================
"""

import argparse
import hashlib
import hmac
import os
import struct
import sys

try:
    from Crypto.Cipher import AES          # pycryptodome
except ImportError:                        # pragma: no cover
    print("[-] 需要 pycryptodome: pip install pycryptodome", file=sys.stderr)
    sys.exit(2)

DEFAULT_KEY_HEX = "8638b511e05b557bf970c418356d44f4"
DEFAULT_SRC = [
    r"D:\csdev-c2\build\sleeve",                  # 从 client jar 直接解出的原始资源
    r"D:\cobalt_strike_4.7\_recon\native\sleeve",
    r"D:\cobalt_strike_4.7\_recon\verify",
]
DEFAULT_OUT = r"D:\csdev-c2\build\sleeve_dec"

MACH_X64 = 0x8664
MACH_X86 = 0x014C


def sleeve_decrypt(blob: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    """解开 sleeve 容器, 返回内层明文 (含尾部 'A' 填充)。"""
    if len(blob) < 64:
        raise ValueError("too-short")
    iv, ct, tag = blob[:16], blob[16:-16], blob[-16:]
    if len(ct) % 16:
        raise ValueError("ciphertext-not-aligned")
    if hmac.new(hmac_key, iv + ct, hashlib.sha256).digest()[:16] != tag:
        raise ValueError("hmac-mismatch")
    return AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct)


def rebuild_coff(inner: bytes, machine: int) -> bytes:
    """把内层 (缺 8 字节头的 COFF) 还原成标准目标文件。"""
    if len(inner) < 12:
        raise ValueError("inner-too-short")

    symptr, nsym, _resv = struct.unpack_from("<III", inner, 0)

    # 节表从内层偏移 12 开始。节数无法从头部读出 (NumberOfSections 被剥掉了),
    # 改用两个互相印证的办法确定:
    #   a) 最小非零 PointerToRawData 之前就是节表结束位置;
    #   b) 符号表里最大的 e_scnum 就是节数。
    minraw = None
    off = 12
    n_scan = 0
    while off + 40 <= len(inner):
        name = inner[off:off + 8]
        if name[0] == 0 or not all(32 <= c < 127 or c == 0 for c in name):
            break
        rawptr = struct.unpack_from("<I", inner, off + 20)[0]
        if rawptr and (minraw is None or rawptr < minraw):
            minraw = rawptr
        n_scan += 1
        off += 40
        if minraw is not None and off >= minraw - 8:
            break
    if n_scan == 0:
        raise ValueError("no-section-table")

    nsec = n_scan
    if 0 < symptr - 8 + nsym * 18 <= len(inner):
        mx = 0
        for i in range(nsym):
            scn = struct.unpack_from("<h", inner, symptr - 8 + i * 18 + 12)[0]
            if scn > mx:
                mx = scn
        if mx:
            nsec = max(nsec, mx)

    header = struct.pack("<HHIIIHH", machine, nsec, 0, symptr, nsym, 0, 0)
    return header + inner[12:]


def main() -> int:
    ap = argparse.ArgumentParser(description="CS 4.7 sleeve 资源 -> 标准 COFF")
    ap.add_argument("--key", default=DEFAULT_KEY_HEX, help="master key (hex)")
    ap.add_argument("--src", nargs="*", default=DEFAULT_SRC, help="输入目录 (只读)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="输出目录")
    args = ap.parse_args()

    digest = hashlib.sha256(bytes.fromhex(args.key)).digest()
    aes_key, hmac_key = digest[:16], digest[16:32]

    os.makedirs(args.out, exist_ok=True)
    ok, fail = 0, []

    for d in args.src:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.lower().endswith(".o"):
                continue
            dst = os.path.join(args.out, fn)
            if os.path.exists(dst):
                continue
            with open(os.path.join(d, fn), "rb") as fh:
                blob = fh.read()
            try:
                inner = sleeve_decrypt(blob, aes_key, hmac_key)
            except Exception as exc:                       # noqa: BLE001
                fail.append((fn, "decrypt: %s" % exc))
                continue
            machine = MACH_X64 if ".x64." in fn else (MACH_X86 if ".x86." in fn else 0)
            try:
                out = rebuild_coff(inner, machine)
            except Exception as exc:                       # noqa: BLE001
                fail.append((fn, "rebuild: %s" % exc))
                continue
            with open(dst, "wb") as fh:
                fh.write(out)
            ok += 1

    print("还原成功 %d 个, 失败 %d 个 -> %s" % (ok, len(fail), args.out))
    for fn, why in fail:
        print("  [FAIL] %-34s %s" % (fn, why))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
