/*
 * cs_dev :: probe.c  --  DLL 载体自检探针
 * 加载指定 DLL, 驻留 2 秒后正常退出.
 *   - 未 patch 的模板: DllMain 只做 size==0 快速返回 -> 退出码 0
 *   - 已 patch 的模板: stager 线程执行注入的 int3 -> 进程异常终止 -> 退出码 0x80000003
 * 用退出码即可判定 DLL 载体的 patch 链路是否真正被执行.
 */
#include <windows.h>

int main(int argc, char **argv) {
    HMODULE h;
    if (argc < 2) return 2;
    h = LoadLibraryA(argv[1]);
    if (!h) return 3;
    Sleep(2000);
    return 0;
}
