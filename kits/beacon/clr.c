/*
 * csdev :: clr.c  --  In-process CLR hosting for execute-assembly
 * ==========================================================================
 * Depends on mscoree.dll only (resolved via LoadLibraryA + GetProcAddress),
 * so the static import table is unchanged.
 *
 * NOTE ON NAMING: the COM interface is declared here by hand under the name
 * CSRuntimeHost instead of ICLRRuntimeHost. MinGW ships its own mscoree.h
 * which declares ICLRRuntimeHost only for C++ (the MIDL_INTERFACE macro
 * expands to nothing useful in C), and reusing that name collides with the
 * header's declaration. Hand-rolling under a private name avoids both
 * problems. Layout: IUnknown (3 slots) then ICLRRuntimeHost's own methods
 * in declaration order.
 *
 * NOTE ON ENCODING: this file is intentionally ASCII-only. A previous
 * revision carried multi-byte comments and the compiler mis-tokenised an
 * identifier in the middle of a line; keeping this translation unit plain
 * ASCII removes that class of failure entirely.
 * ==========================================================================
 */
#include <windows.h>

#include "clr.h"

/* ---------------------------------------------------------------- COM */

typedef struct CSRuntimeHost CSRuntimeHost;

typedef struct CSRuntimeHostVtbl {
    /* IUnknown */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(CSRuntimeHost *, const GUID *, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(CSRuntimeHost *);
    ULONG   (STDMETHODCALLTYPE *Release)(CSRuntimeHost *);
    /* ICLRRuntimeHost */
    HRESULT (STDMETHODCALLTYPE *Start)(CSRuntimeHost *);
    HRESULT (STDMETHODCALLTYPE *Stop)(CSRuntimeHost *);
    HRESULT (STDMETHODCALLTYPE *SetHostControl)(CSRuntimeHost *, void *);
    HRESULT (STDMETHODCALLTYPE *GetCLRControl)(CSRuntimeHost *, void **);
    HRESULT (STDMETHODCALLTYPE *UnloadAppDomain)(CSRuntimeHost *, DWORD, BOOL);
    HRESULT (STDMETHODCALLTYPE *ExecuteInAppDomain)(CSRuntimeHost *, DWORD, void *, void *, void **);
    HRESULT (STDMETHODCALLTYPE *GetCurrentAppDomainId)(CSRuntimeHost *, DWORD *);
    HRESULT (STDMETHODCALLTYPE *ExecuteApplication)(CSRuntimeHost *, LPCWSTR, DWORD,
                                                    LPCWSTR *, LPCWSTR *, LPCWSTR, DWORD *);
    HRESULT (STDMETHODCALLTYPE *ExecuteInDefaultAppDomain)(CSRuntimeHost *, LPCWSTR, LPCWSTR,
                                                           LPCWSTR, LPCWSTR, DWORD *);
} CSRuntimeHostVtbl;

struct CSRuntimeHost {
    const CSRuntimeHostVtbl *lpVtbl;
};

typedef HRESULT (STDAPICALLTYPE *CorBindToRuntimeEx_t)(LPCWSTR, LPCWSTR, DWORD,
                                                       const GUID *, const GUID *, void **);

/* {90F1A06E-7712-4762-86B5-7A5EBA6BDB02} CLSID_CLRRuntimeHost */
static const GUID g_clsid_runtime_host =
    { 0x90F1A06E, 0x7712, 0x4762, { 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02 } };
/* {90F1A06C-7712-4762-86B5-7A5EBA6BDB02} IID_ICLRRuntimeHost */
static const GUID g_iid_runtime_host =
    { 0x90F1A06C, 0x7712, 0x4762, { 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02 } };

/* ---------------------------------------------------------------- helpers */

static int c_to_wide(const char *src, WCHAR *dst, unsigned int cap)
{
    unsigned int i = 0;
    if (!src || cap == 0) return 0;
    while (src[i] && i + 1 < cap) {
        unsigned char ch = (unsigned char)src[i];
        /* only ASCII travels this path (base64 / paths / args) */
        dst[i] = (ch < 0x80) ? (WCHAR)ch : (WCHAR)'?';
        i++;
    }
    dst[i] = 0;
    return 1;
}

static int c_strlen(const char *s)
{
    int n = 0;
    while (s && s[n]) n++;
    return n;
}

/* ---------------------------------------------------------------- main */

int clr_execute_in_dll(const char *stubPath, const char *typeName,
                       const char *method, const char *arg, int *retOut)
{
    static HMODULE s_mscoree = NULL;
    static CSRuntimeHost *s_rhost = NULL;
    static int s_state = 0;             /* 0 = fresh, 1 = ready, 2 = failed */
    CorBindToRuntimeEx_t bind;
    HRESULT hr;
    WCHAR *wstub = NULL;
    WCHAR *wtype = NULL;
    WCHAR *wmeth = NULL;
    WCHAR *warg = NULL;
    DWORD ret = 0;
    int arglen;
    int rc = 0;

    if (retOut) *retOut = -1;
    if (!stubPath || !typeName || !method) return 1;

    /* one-time init: load CLR and Start it (it then stays in this process) */
    if (s_state == 0) {
        s_mscoree = LoadLibraryA("mscoree.dll");
        if (!s_mscoree) { s_state = 2; return 2; }

        bind = (CorBindToRuntimeEx_t)GetProcAddress(s_mscoree, "CorBindToRuntimeEx");
        if (!bind) bind = (CorBindToRuntimeEx_t)GetProcAddress(s_mscoree, "CorBindToRuntime");
        if (!bind) { s_state = 2; return 3; }

        hr = bind(L"v4.0.30319", L"wks", 0,
                  &g_clsid_runtime_host, &g_iid_runtime_host, (void **)&s_rhost);
        if (FAILED(hr) || !s_rhost) {
            /* fall back: let the CLR pick whatever version is installed */
            hr = bind(NULL, NULL, 0,
                      &g_clsid_runtime_host, &g_iid_runtime_host, (void **)&s_rhost);
        }
        if (FAILED(hr) || !s_rhost) { s_state = 2; return 4; }

        hr = s_rhost->lpVtbl->Start(s_rhost);
        if (FAILED(hr)) {
            s_rhost->lpVtbl->Release(s_rhost);
            s_rhost = NULL;
            s_state = 2;
            return 5;
        }
        s_state = 1;
    }
    if (s_state != 1) return 6;

    /* the arg may be large (base64 of the target assembly), allocate on demand */
    arglen = c_strlen(arg);
    wstub = (WCHAR *)VirtualAlloc(NULL, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    wtype = (WCHAR *)VirtualAlloc(NULL, 512, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    wmeth = (WCHAR *)VirtualAlloc(NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    warg  = (WCHAR *)VirtualAlloc(NULL, (SIZE_T)(arglen + 2) * sizeof(WCHAR),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!wstub || !wtype || !wmeth || !warg) { rc = 7; goto done; }

    c_to_wide(stubPath, wstub, 1024);
    c_to_wide(typeName, wtype, 256);
    c_to_wide(method, wmeth, 128);
    c_to_wide(arg ? arg : "", warg, (unsigned int)arglen + 1);

    hr = s_rhost->lpVtbl->ExecuteInDefaultAppDomain(s_rhost, wstub, wtype, wmeth, warg, &ret);
    if (FAILED(hr)) {
        rc = 8;
        goto done;
    }
    if (retOut) *retOut = (int)ret;

done:
    if (wstub) VirtualFree(wstub, 0, MEM_RELEASE);
    if (wtype) VirtualFree(wtype, 0, MEM_RELEASE);
    if (wmeth) VirtualFree(wmeth, 0, MEM_RELEASE);
    if (warg)  VirtualFree(warg, 0, MEM_RELEASE);
    return rc;
}
