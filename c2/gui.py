#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
csdev :: gui.py  --  桌面控制台 (tkinter, 零依赖)

连接 c2/server.py 的 Web API, 提供服务端界面。
界面结构参考专业 C2 客户端:
    左侧   会话树 (按主机分组, 显示状态/空闲时间)
    右上   终端   (命令回显 + 输出流)
    右下   文件浏览器 / 进程列表 (标签页切换)

用法:
    python gui.py
    python gui.py --server http://1.2.3.4:8443
"""
import argparse
import json
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from urllib.request import Request, urlopen
from urllib.error import URLError

# ---------------------------------------------------------------- 视觉
BG      = "#0d1117"
PANEL   = "#161b22"
PANEL2  = "#1c2128"
LINE    = "#30363d"
FG      = "#c9d1d9"
DIM     = "#8b949e"
ACCENT  = "#58a6ff"
OK      = "#3fb950"
WARN    = "#d29922"
ERR     = "#f85149"
MONO    = ("Consolas", 10)
UI      = ("Microsoft YaHei UI", 9)
UI_B    = ("Microsoft YaHei UI", 10, "bold")
UI_S    = ("Microsoft YaHei UI", 8)


class Api:
    def __init__(self, base):
        self.base = base.rstrip("/")

    def _req(self, path, data=None):
        url = self.base + path
        try:
            if data is not None:
                body = json.dumps(data).encode("utf-8")
                r = Request(url, data=body, headers={"Content-Type": "application/json"})
            else:
                r = Request(url)
            with urlopen(r, timeout=6) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except URLError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def sessions(self):
        return self._req("/api/sessions")

    def output(self, sid, since=0):
        return self._req("/api/output?sid=%s&since=%s" % (sid, since))

    def command(self, sid, cmd):
        return self._req("/api/command", {"sid": sid, "cmd": cmd})

    def kill(self, sid):
        return self._req("/api/kill", {"sid": sid})


class App:
    def __init__(self, root, api):
        self.root = root
        self.api = api
        self.sessions = {}
        self.cur = None
        self.since = 0.0
        self._build()

    # ------------------------------------------------------------ 构建
    def _build(self):
        r = self.root
        r.title("csdev C2 控制台")
        r.geometry("1180x720")
        r.configure(bg=BG)
        r.minsize(900, 560)

        # ---- 顶栏 ----
        top = tk.Frame(r, bg=PANEL, height=44)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)

        tk.Label(top, text="csdev", bg=PANEL, fg=ACCENT,
                 font=("Consolas", 14, "bold")).pack(side="left", padx=(16, 4), pady=8)
        tk.Label(top, text="C2", bg=PANEL, fg=FG,
                 font=("Consolas", 14)).pack(side="left", pady=8)

        self.lbl_stat = tk.Label(top, text="● 连接中", bg=PANEL, fg=WARN, font=UI)
        self.lbl_stat.pack(side="right", padx=16)

        self.lbl_cnt = tk.Label(top, text="会话 0", bg=PANEL, fg=DIM, font=UI)
        self.lbl_cnt.pack(side="right", padx=8)

        # ---- 主体 ----
        body = tk.Frame(r, bg=BG)
        body.pack(fill="both", expand=True)

        # 左侧会话树
        left = tk.Frame(body, bg=PANEL, width=260)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        tk.Label(left, text="会话列表", bg=PANEL, fg=DIM,
                 font=UI_S, anchor="w").pack(fill="x", padx=14, pady=(12, 6))

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Sess.Treeview",
                        background=PANEL, fieldbackground=PANEL,
                        foreground=FG, borderwidth=0, font=UI, rowheight=44)
        style.map("Sess.Treeview",
                  background=[("selected", PANEL2)],
                  foreground=[("selected", ACCENT)])
        style.configure("Sess.Treeview.Heading",
                        background=PANEL, foreground=DIM, borderwidth=0, font=UI_S)

        self.tree = ttk.Treeview(left, style="Sess.Treeview",
                                 columns=("host",), show="tree", selectmode="browse")
        self.tree.pack(fill="both", expand=True, padx=6, pady=6)
        self.tree.bind("<<TreeviewSelect>>", self._on_pick)

        # 右侧
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        # 会话信息条
        bar = tk.Frame(right, bg=PANEL, height=36)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        self.lbl_sess = tk.Label(bar, text="未选择会话", bg=PANEL, fg=FG,
                                 font=UI, anchor="w")
        self.lbl_sess.pack(side="left", padx=14)

        # 标签页
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=DIM,
                        padding=(16, 7), font=UI, borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", PANEL2)],
                  foreground=[("selected", ACCENT)])

        nb = ttk.Notebook(right, style="TNotebook")
        nb.pack(fill="both", expand=True, padx=10, pady=(6, 10))

        # --- 终端页 ---
        t_tab = tk.Frame(nb, bg=BG)
        nb.add(t_tab, text="终端")
        self.term = tk.Text(t_tab, bg=BG, fg=FG, font=MONO, bd=0,
                            wrap="word", insertbackground=ACCENT,
                            padx=12, pady=10, state="disabled")
        self.term.pack(fill="both", expand=True)
        self.term.tag_config("cmd", foreground=ACCENT)
        self.term.tag_config("sys", foreground=DIM)
        self.term.tag_config("err", foreground=ERR)

        inp = tk.Frame(t_tab, bg=PANEL, height=48)
        inp.pack(fill="x")
        inp.pack_propagate(False)
        self.entry = tk.Entry(inp, bg=PANEL2, fg=FG, font=MONO, bd=0,
                              insertbackground=ACCENT, relief="flat")
        self.entry.pack(side="left", fill="both", expand=True, padx=(12, 6), pady=9)
        self.entry.bind("<Return>", lambda e: self._send())
        self.entry.bind("<Up>", self._hist_up)
        self.entry.bind("<Down>", self._hist_down)
        self.hist = []
        self.hist_i = -1

        btn = tk.Button(inp, text="发送", bg=ACCENT, fg=BG, font=UI_B,
                        bd=0, padx=20, cursor="hand2", command=self._send)
        btn.pack(side="right", padx=(0, 12), pady=9)

        # --- 进程页 ---
        p_tab = tk.Frame(nb, bg=BG)
        nb.add(p_tab, text="进程")
        pbar = tk.Frame(p_tab, bg=PANEL, height=40)
        pbar.pack(fill="x")
        pbar.pack_propagate(False)
        tk.Button(pbar, text="刷新", bg=PANEL2, fg=FG, font=UI, bd=0,
                  padx=16, cursor="hand2",
                  command=lambda: self._send_raw("ps")).pack(side="left", padx=10, pady=7)
        tk.Button(pbar, text="结束进程", bg=PANEL2, fg=ERR, font=UI, bd=0,
                  padx=16, cursor="hand2",
                  command=self._kill_proc).pack(side="left", pady=7)
        style.configure("P.Treeview", background=BG, fieldbackground=BG,
                        foreground=FG, font=MONO, borderwidth=0, rowheight=22)
        self.procs = ttk.Treeview(p_tab, style="P.Treeview",
                                  columns=("pid", "name"), show="headings")
        self.procs.heading("pid", text="PID")
        self.procs.heading("name", text="进程名")
        self.procs.column("pid", width=90, anchor="e")
        self.procs.column("name", width=420, anchor="w")
        self.procs.pack(fill="both", expand=True, padx=10, pady=8)

        # --- 文件页 ---
        f_tab = tk.Frame(nb, bg=BG)
        nb.add(f_tab, text="文件")
        fbar = tk.Frame(f_tab, bg=PANEL, height=40)
        fbar.pack(fill="x")
        fbar.pack_propagate(False)
        self.path_var = tk.StringVar(value="C:\\")
        tk.Entry(fbar, textvariable=self.path_var, bg=PANEL2, fg=FG, font=MONO,
                 bd=0, relief="flat").pack(side="left", fill="x",
                                           expand=True, padx=(10, 6), pady=7)
        tk.Button(fbar, text="列出", bg=PANEL2, fg=FG, font=UI, bd=0, padx=14,
                  cursor="hand2", command=self._ls_files).pack(side="left", pady=7)
        tk.Button(fbar, text="下载", bg=PANEL2, fg=OK, font=UI, bd=0, padx=14,
                  cursor="hand2", command=self._dl_file).pack(side="left", padx=6, pady=7)

        self.files = tk.Text(f_tab, bg=BG, fg=FG, font=MONO, bd=0,
                             wrap="none", padx=12, pady=10)
        self.files.pack(fill="both", expand=True)

        # 底部状态栏
        self.status = tk.Label(r, text="就绪", bg=PANEL, fg=DIM, font=UI_S,
                               anchor="w")
        self.status.pack(fill="x", side="bottom", ipady=4)

    # ------------------------------------------------------------ 逻辑
    def set_status(self, msg, color=DIM):
        self.status.config(text=msg, fg=color)

    def _on_pick(self, _):
        sel = self.tree.selection()
        if not sel:
            return
        sid = sel[0]
        if sid == self.cur:
            return
        self.cur = sid
        self.since = 0.0
        self._clear_term()
        s = self.sessions.get(sid, {})
        self.lbl_sess.config(
            text="%s   %s\\%s   %s   %s" % (sid, s.get("host", "?"),
                                           s.get("user", "?"),
                                           s.get("arch", "?"),
                                           s.get("addr", "")))
        self._append_term("[*] 已切换到会话 %s\n" % sid, "sys")

    def _clear_term(self):
        self.term.config(state="normal")
        self.term.delete("1.0", "end")
        self.term.config(state="disabled")

    def _append_term(self, text, tag=None):
        self.term.config(state="normal")
        self.term.insert("end", text, tag or "")
        self.term.see("end")
        self.term.config(state="disabled")

    def _send(self):
        cmd = self.entry.get().strip()
        if not cmd:
            return
        self.entry.delete(0, "end")
        if not self.cur:
            self.set_status("请先选择一个会话", WARN)
            return
        self.hist.append(cmd)
        self.hist_i = len(self.hist)
        self._append_term("> %s\n" % cmd, "cmd")
        res = self.api.command(self.cur, cmd)
        if not res.get("ok"):
            self._append_term("[!] 下发失败: %s\n" % res.get("error", "?"), "err")

    def _send_raw(self, cmd):
        if not self.cur:
            self.set_status("请先选择一个会话", WARN)
            return
        self._append_term("> %s\n" % cmd, "cmd")
        self.api.command(self.cur, cmd)

    def _hist_up(self, _):
        if self.hist and self.hist_i > 0:
            self.hist_i -= 1
            self.entry.delete(0, "end")
            self.entry.insert(0, self.hist[self.hist_i])

    def _hist_down(self, _):
        if self.hist_i < len(self.hist) - 1:
            self.hist_i += 1
            self.entry.delete(0, "end")
            self.entry.insert(0, self.hist[self.hist_i])
        else:
            self.hist_i = len(self.hist)
            self.entry.delete(0, "end")

    def _ls_files(self):
        p = self.path_var.get().strip() or "C:\\"
        self._send_raw('dir "%s"' % p)

    def _dl_file(self):
        if not self.cur:
            return
        name = simpledialog.askstring("下载文件", "输入完整路径:", parent=self.root)
        if name:
            self._send_raw("download %s" % name)

    def _kill_proc(self):
        sel = self.procs.selection()
        if not sel:
            self.set_status("请先选中一个进程", WARN)
            return
        pid = self.procs.item(sel[0], "values")[0]
        if messagebox.askyesno("确认", "结束进程 PID %s ?" % pid):
            self._send_raw("taskkill /F /PID %s" % pid)

    # ------------------------------------------------------------ 轮询
    def poll(self):
        self._poll_sessions()
        self._poll_output()
        self.root.after(2000, self.poll)

    def _poll_sessions(self):
        res = self.api.sessions()
        if not res.get("ok"):
            self.lbl_stat.config(text="● 服务端离线", fg=ERR)
            return
        self.lbl_stat.config(text="● 已连接", fg=OK)
        lst = res.get("sessions", [])
        self.lbl_cnt.config(text="会话 %d" % len(lst))
        self.sessions = {s["sid"]: s for s in lst}

        # 重建树 (保留选中)
        sel = self.tree.selection()
        for i in self.tree.get_children():
            self.tree.delete(i)
        for s in lst:
            idle = s.get("idle", 0)
            mark = "●" if idle < 30 else "○"
            self.tree.insert(
                "", "end", iid=s["sid"],
                text=" %s %s\n     %s\\%s  %ss前" % (
                    mark, s.get("host", "?"), s.get("host", "?"),
                    s.get("user", "?"), idle))
        if sel and sel[0] in self.sessions:
            self.tree.selection_set(sel[0])

    def _poll_output(self):
        if not self.cur:
            return
        res = self.api.output(self.cur, self.since)
        if not res.get("ok"):
            return
        items = res.get("items", [])
        if not items:
            return
        for ts, txt in items:
            self.since = max(self.since, ts)
            txt = txt.replace("\r", "")
            if txt.startswith("> "):
                continue  # 已本地回显
            tag = None
            if "无法" in txt or "[-]" in txt:
                tag = "err"
            self._append_term(txt if txt.endswith("\n") else txt + "\n", tag)

        # 若是 ps 输出, 填充进程表
        joined = "".join(t for _, t in items)
        if "\t" in joined and self.procs.get_children() == ():
            self._fill_procs(joined)

    def _fill_procs(self, text):
        for line in text.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0].strip().isdigit():
                self.procs.insert("", "end", values=(parts[0].strip(), parts[1].strip()))


def main():
    ap = argparse.ArgumentParser(description="csdev C2 桌面控制台")
    ap.add_argument("--server", default="http://127.0.0.1:8443")
    a = ap.parse_args()

    root = tk.Tk()
    app = App(root, Api(a.server))
    root.after(500, app.poll)
    app.set_status("已连接 %s" % a.server, OK)
    root.mainloop()


if __name__ == "__main__":
    main()
