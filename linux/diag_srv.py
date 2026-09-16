#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cs_dev :: diag_srv.py -- 协议诊断: 打印原始字节 vs 解密结果"""
import socket, struct, sys

KEY = bytes([0x91, 0x3A, 0x77, 0xC4, 0x0E, 0x5B, 0xD2, 0x18,
             0x6F, 0xA3, 0x44, 0xBC, 0x27, 0xE8, 0x05, 0x9D])
MAGIC = 0x4B52424B


def rc4(data, key):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data)); a = b = 0
    for x, c in enumerate(data):
        a = (a + 1) & 0xFF
        b = (b + S[a]) & 0xFF
        S[a], S[b] = S[b], S[a]
        out[x] = c ^ S[(S[a] + S[b]) & 0xFF]
    return bytes(out)


def rx(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


# --- 自检: Python 能否解开 C 生成的密文 --------------------------------
CT = bytes.fromhex("a1a924f4653e2571859bbc32f018f1d6f101276c4a153131c0dfb20bf1ebe7fd"
                   "bcfd2cc6b911c7b55b0e03322f482808bb54016366e3e8dc90c1")
print("[self-test] Py decrypt of C ciphertext:")
try:
    print("            ", rc4(CT, KEY).decode())
except Exception as e:
    print("            FAILED", e)

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8443))
srv.listen(1)
srv.settimeout(25)
print("[*] diag C2 on 8443", flush=True)

conn, addr = srv.accept()
print(f"[+] conn from {addr}", flush=True)

hdr = rx(conn, 8)
magic, n = struct.unpack(">II", hdr)
print(f"[i] magic={magic:#x} (expect {MAGIC:#x})  n={n}")

raw = rx(conn, n)
print(f"[i] raw len={len(raw)}")
print(f"[i] raw hex  = {raw[:48].hex()}")
print(f"[i] raw repr = {raw[:64]!r}")
dec = rc4(raw, KEY)
print(f"[i] dec repr = {dec[:64]!r}")
try:
    print(f"[i] dec utf8 = {dec.decode('utf-8')}")
except Exception as e:
    print(f"[i] dec utf8 FAILED: {e}")
conn.close(); srv.close()
