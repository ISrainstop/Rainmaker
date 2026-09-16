/*
 * cs_dev :: dllentry_test.c  --  验证 MinGW 下哪条路径能真正触发 DLL 载入逻辑
 * 用 -DTEST_CUSTOM_ENTRY 切换:
 *   默认           : BOOL WINAPI DllMain(...)              依赖 dllcrt2.o
 *   TEST_CUSTOM_ENTRY: BOOL WINAPI _DllMainCRTStartup(...) 自提供入口(-nostartfiles)
 * 两条路径都往固定路径写标记文件, 由外部检查是否存在.
 */
#include <windows.h>

static void marker(const char *tag) {
    char path[260];
    int i = 0;
    const char *a = "C:\\Users\\Public\\csdev_dll_";
    const char *s;
    HANDLE f;
    for (s = a; *s; s++) path[i++] = *s;
    for (s = tag; *s; s++) path[i++] = *s;
    path[i] = 0;
    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
}

#ifdef TEST_CUSTOM_ENTRY
/* 自提供 DLL 入口: 编译用 -nostartfiles, 不链接 dllcrt2.o */
BOOL WINAPI _DllMainCRTStartup(HANDLE hDll, DWORD reason, LPVOID reserved) {
    (void)hDll; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) marker("custom.txt");
    return TRUE;
}
#else
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)hInst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) marker("default.txt");
    return TRUE;
}
#endif
