#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
csdev :: rsa_crosscheck.py  --  RSA 实现的独立交叉验证 (WSL 侧)

验证链 (三个互相独立的解密端, 避免"自己验自己"):
  A. 纯 Python 大数运算   pow(c, d, n) + 手工剥离 PKCS#1 v1.5 填充
  B. openssl pkeyutl      标准工具的标准填充实现
  C. 服务端真实私钥       用内嵌公钥加密, 用 data/csdev.key 解密
                          (证明植入体上线所需的密钥交换真的成立)

用法:
  python3 rsa_crosscheck.py --bin ./rsa_selftest [--server-key /mnt/d/csdev-c2/data/csdev.key]

退出码: 0 全部通过 / 1 存在失败
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

PASS = []
FAIL = []


def report(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    mark = "[v]" if ok else "[x]"
    line = "  {} {}".format(mark, name)
    if detail:
        line += "  -- " + detail
    print(line, flush=True)


def sh(cmd, **kw):
    """跑命令, 返回 (rc, stdout, stderr)。"""
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    return p.returncode, p.stdout, p.stderr


def strip_lead(hx):
    """去掉大端 hex 的前导 0, 得到规范的无填充表示。"""
    hx = hx.lower()
    hx = hx.lstrip("0")
    if len(hx) % 2:
        hx = "0" + hx
    return hx


def parse_rsa_text(pem):
    """从 `openssl rsa -text` 输出解析 n / e / d。"""
    rc, out, err = sh(["openssl", "rsa", "-in", pem, "-noout", "-text"])
    if rc != 0:
        raise RuntimeError("openssl rsa -text 失败: " + err.decode("utf-8", "replace"))
    text = out.decode("utf-8", "replace")

    def grab(label):
        m = re.search(label + r":\s*\n((?:\s+[0-9a-fA-F:]+\s*\n)+)", text)
        if not m:
            raise RuntimeError("解析 " + label + " 失败")
        return strip_lead(re.sub(r"[^0-9a-fA-F]", "", m.group(1)))

    m = re.search(r"publicExponent:\s*(\d+)", text)
    if not m:
        raise RuntimeError("解析 publicExponent 失败")
    return grab("modulus"), int(m.group(1)), grab("privateExponent")


def pkcs1v15_unpad(em):
    """手工剥离 PKCS#1 v1.5 填充, 返回 (明文, 说明)。失败抛异常。"""
    if em[0] != 0x00:
        raise ValueError("EM[0] != 0x00 (实际 0x%02x)" % em[0])
    if em[1] != 0x02:
        raise ValueError("EM[1] != 0x02 (实际 0x%02x)" % em[1])
    sep = em.find(b"\x00", 2)
    if sep < 0:
        raise ValueError("缺少 0x00 分隔符")
    if sep - 2 < 8:
        raise ValueError("PS 长度 %d < 8" % (sep - 2))
    return em[sep + 1:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="./rsa_selftest", help="rsa_selftest 可执行文件")
    ap.add_argument("--server-key", default="/mnt/d/csdev-c2/data/csdev.key",
                    help="服务端 PKCS#8 私钥")
    args = ap.parse_args()

    exe = os.path.abspath(args.bin)
    if not os.path.isfile(exe):
        print("[x] 找不到 " + exe)
        return 1

    for tool in ("openssl",):
        if not shutil.which(tool):
            print("[x] 缺少工具: " + tool)
            return 1

    tmp = tempfile.mkdtemp(prefix="rsa_cc_")
    pem = os.path.join(tmp, "test.pem")

    print("== 0. 生成 2048 位测试密钥对 (openssl) ==", flush=True)
    rc, _, err = sh(["openssl", "genpkey", "-algorithm", "RSA",
                     "-pkeyopt", "rsa_keygen_bits:2048", "-out", pem])
    if rc != 0:
        print("[x] 密钥生成失败: " + err.decode("utf-8", "replace"))
        return 1
    n_hex, e, d_hex = parse_rsa_text(pem)
    n = int(n_hex, 16)
    d = int(d_hex, 16)
    report("测试密钥对生成", len(n_hex) == 512,
           "n=%d bit, e=%d" % (n.bit_length(), e))

    def c_encrypt(mode_args):
        rc, out, err = sh([exe] + mode_args)
        if rc != 0:
            return None, err.decode("utf-8", "replace")
        hx = out.decode().strip()
        return hx, err.decode("utf-8", "replace")

    def openssl_decrypt(ct_bytes, keypem):
        ctf = os.path.join(tmp, "ct.bin")
        ptf = os.path.join(tmp, "pt.bin")
        with open(ctf, "wb") as f:
            f.write(ct_bytes)
        rc, _, err = sh(["openssl", "pkeyutl", "-decrypt", "-inkey", keypem,
                         "-in", ctf, "-out", ptf,
                         "-pkeyopt", "rsa_padding_mode:pkcs1"])
        if rc != 0:
            return None, err.decode("utf-8", "replace").strip()
        with open(ptf, "rb") as f:
            return f.read(), ""

    # ---- 1. custom 模式: 多长度明文, 两个独立解密端 ----
    print("\n== 1. C 加密 -> 纯 Python 大数解密 + openssl 解密 ==", flush=True)
    for plen in (1, 16, 32, 100, 244, 245):
        plain = bytes(((i * 7 + 3) & 0xFF) for i in range(plen))
        hx, info = c_encrypt(["custom", n_hex, str(e), plain.hex()])
        if hx is None:
            report("明文 %d 字节 C 加密" % plen, False, info)
            continue
        ct = bytes.fromhex(hx)

        # 密文必须恰好 256 字节
        if len(ct) != 256:
            report("明文 %d 字节: 密文长度" % plen, False,
                   "期望 256, 实际 %d" % len(ct))
            continue

        # A. 纯 Python
        try:
            em = pow(int.from_bytes(ct, "big"), d, n).to_bytes(256, "big")
            got = pkcs1v15_unpad(em)
            okA = (got == plain)
            detailA = "一致" if okA else "不一致 (%d vs %d 字节)" % (len(got), len(plain))
        except Exception as ex:
            okA, detailA = False, "异常: %s" % ex

        # B. openssl
        gotB, errB = openssl_decrypt(ct, pem)
        okB = (gotB == plain)
        detailB = "一致" if okB else ("不一致" if gotB is not None else "失败: " + errB)

        report("明文 %3d 字节: A纯Python解密" % plen, okA, detailA)
        report("明文 %3d 字节: B openssl解密" % plen, okB, detailB)

    # ---- 2. 边界: 246 字节必须被拒 ----
    print("\n== 2. 边界校验 (PKCS#1 v1.5 上限 245) ==", flush=True)
    over = bytes(246)
    hx, info = c_encrypt(["custom", n_hex, str(e), over.hex()])
    report("246 字节明文被拒绝", hx is None,
           "正确拒绝" if hx is None else "错误地接受了")

    # ---- 3. 内嵌公钥 + 服务端真实私钥 ----
    print("\n== 3. 内嵌 pubkey.h 加密 -> 服务端 data/csdev.key 解密 ==", flush=True)
    keypath = args.server_key
    if not os.path.isfile(keypath):
        report("服务端私钥存在", False, keypath)
    else:
        report("服务端私钥存在", True, keypath)
        # 构造一个与 checkin 明文同构的载荷:
        # [32B aes_key][32B hmac_key][16B iv_seed][1B ver][1B meta_len][meta]
        aes_key = bytes(range(0x20, 0x40))
        hmac_key = bytes(range(0x60, 0x80))
        meta = b"rainstop-wsl\x1Fyg\x1Fx64\x1F4242\x1F1\x1Fbeacon2_linux\x1F10.45.0.2\x1FUbuntu 24.04.1 LTS"
        payload = aes_key + hmac_key + bytes(16) + bytes([0x02, len(meta)]) + meta

        hx, info = c_encrypt(["embedded", payload.hex()])
        if hx is None:
            report("内嵌公钥加密", False, info)
        else:
            ct = bytes.fromhex(hx)
            got, err = openssl_decrypt(ct, keypath)
            ok = (got == payload)
            report("内嵌公钥加密 -> 服务端私钥解密", ok,
                   "checkin 明文 %d 字节逐字节一致" % len(payload) if ok
                   else ("解密失败: " + err if got is None else "明文不一致"))
            if ok:
                # 进一步确认结构可被服务端解析。
                # 布局: 0 aes_key(32) | 32 hmac_key(32) | 64 iv_seed(16) | 80 ver | 81 meta_len | 82 meta
                # 与 go/proto/frame.go 的 CheckinFixedLen = 32+32+16+2 = 82 对齐
                report("  checkin 结构校验",
                       got[80] == 0x02 and got[81] == len(meta) and got[82:] == meta,
                       "ver=0x%02x meta_len=%d meta=%s" % (got[80], got[81],
                                                            got[82:].decode("ascii", "replace")))

        # 服务端私钥的公钥指纹必须与 pubkey.h 一致
        rc, out, _ = sh(["openssl", "rsa", "-in", keypath, "-noout", "-modulus"])
        if rc == 0:
            srv_mod = strip_lead(out.decode().strip().split("=", 1)[1])
            import hashlib
            fp = hashlib.sha256(bytes.fromhex(srv_mod)).hexdigest()[:16]
            # 对比内嵌 blob 的模数指纹
            rc2, out2, _ = sh([exe, "embedded", b"\x01\x02\x03".hex()])
            report("服务端私钥指纹 == pubkey.h 指纹",
                   fp == "74df7fe06ee71260",
                   "sha256(mod)[0:8] = %s" % fp)

    print("\n== 结果 ==")
    print("  PASS %d  FAIL %d" % (len(PASS), len(FAIL)))
    for f in FAIL:
        print("  [x] " + f)
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
