/*
 * csdev :: tools/bof_test.c  --  BOF (COFF) 加载器控制台自测程序
 * ==========================================================================
 * 用法:
 *   bof_test.exe dump  <file.o>              打印 COFF 结构 (头/节表/符号/重定位)
 *   bof_test.exe probe <file.o>              只解析不执行, 报告入口与符号解析结果
 *   bof_test.exe run   <file.o> [arg ...]    真实加载执行, 参数按 BOF 约定打包
 *   bof_test.exe scan  <dir|file> ...        批量统计可解析性 (样本验收用)
 *
 * 编译 (在 D:\csdev-c2 下):
 *   gcc -O2 -Wall -I kits/beacon -o build/bof_test.exe \
 *       tools/bof_test.c kits/beacon/bof.c kits/beacon/bof_api.c
 * ==========================================================================
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../kits/beacon/bof.h"

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif

/* ------------------------------------------------------------- 读字节序 */

static unsigned int r16(const unsigned char *p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8);
}

static unsigned int r32(const unsigned char *p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

/* ------------------------------------------------------- 控制台 UTF-8 */

static void console_utf8(void)
{
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
}

/* Windows 上 main 的 argv 是 ANSI 编码 (中文会变成 GBK/CP936), 直接按字节
 * 传给 BOF 就与 UTF-8 约定不符。这里用 CommandLineToArgvW 取回宽字符参数,
 * 再统一转成 UTF-8。shell32 通过 GetProcAddress 动态解析, 不进入静态导入。 */
static char **argv_utf8(int *argc_io)
{
    typedef LPWSTR *(WINAPI *clta_t)(LPCWSTR, int *);
    HMODULE   sh;
    clta_t    clta;
    int       argc = 0;
    LPWSTR   *wargv;
    char    **argv;
    int       i;

    sh = LoadLibraryA("shell32.dll");
    if (!sh) return NULL;
    *(FARPROC *)&clta = GetProcAddress(sh, "CommandLineToArgvW");
    if (!clta) { FreeLibrary(sh); return NULL; }

    wargv = clta(GetCommandLineW(), &argc);
    if (!wargv || argc <= 0) { FreeLibrary(sh); return NULL; }

    argv = (char **)malloc(sizeof(char *) * (size_t)(argc + 1));
    if (!argv) { LocalFree(wargv); FreeLibrary(sh); return NULL; }

    for (i = 0; i < argc; i++) {
        int n = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, NULL, 0, NULL, NULL);
        argv[i] = (char *)malloc((size_t)(n > 0 ? n : 1));
        if (!argv[i]) { argv[i] = (char *)""; continue; }
        if (n > 0) WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, argv[i], n, NULL, NULL);
        else       argv[i][0] = 0;
    }
    argv[argc] = NULL;

    LocalFree(wargv);
    FreeLibrary(sh);
    *argc_io = argc;
    return argv;
}

/* ------------------------------------------------------------ 文件读取 */

static unsigned char *read_file(const char *path, unsigned int *outlen)
{
    FILE *f = fopen(path, "rb");
    long  n;
    unsigned char *b;

    *outlen = 0;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    n = ftell(f);
    if (n <= 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

    b = (unsigned char *)malloc((size_t)n);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
    fclose(f);
    *outlen = (unsigned int)n;
    return b;
}

/* ------------------------------------------------------------ 诊断输出 */

static void on_diag(const char *msg)
{
    printf("      %s\n", msg);
}

/* --------------------------------------------------------------- dump */

static const char *machine_name(unsigned int m)
{
    switch (m) {
    case 0x8664: return "AMD64";
    case 0x014C: return "I386";
    case 0xAA64: return "ARM64";
    default:     return "其他";
    }
}

static void sec_flags(unsigned int ch, char *out, unsigned int cap)
{
    unsigned int n = 0;
    struct { unsigned int bit; const char *nm; } tab[] = {
        { 0x00000020u, "CODE"   }, { 0x00000040u, "IDATA"  },
        { 0x00000080u, "UDATA"  }, { 0x00000200u, "INFO"   },
        { 0x00000800u, "REMOVE" }, { 0x00001000u, "COMDAT" },
        { 0x02000000u, "DISCARD"}, { 0x20000000u, "EXEC"   },
        { 0x40000000u, "READ"   }, { 0x80000000u, "WRITE"  }
    };
    unsigned int i;
    out[0] = 0;
    for (i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        if (ch & tab[i].bit) {
            const char *s = tab[i].nm;
            while (*s && n < cap - 2) out[n++] = *s++;
            if (n < cap - 2) out[n++] = '|';
        }
    }
    if (n == 0) { out[n++] = '-'; }
    out[n] = 0;
}

static int cmd_dump(const unsigned char *b, unsigned int n)
{
    unsigned int machine, nsec, ts, symptr, nsym, optsz, chars, strtab;
    unsigned int i, r, total_rel = 0;

    if (n < BOF_COFF_HDR_SIZE) { printf("[-] 文件太小, 不是 COFF\n"); return 1; }

    machine = r16(b);
    nsec    = r16(b + 2);
    ts      = r32(b + 4);
    symptr  = r32(b + 8);
    nsym    = r32(b + 12);
    optsz   = r16(b + 16);
    chars   = r16(b + 18);

    printf("=== COFF 文件头 (20 字节) ===\n");
    printf("  Machine              = 0x%04x (%s)\n", machine, machine_name(machine));
    printf("  NumberOfSections     = %u\n", nsec);
    printf("  TimeDateStamp        = 0x%08x (%u)\n", ts, ts);
    printf("  PointerToSymbolTable = 0x%08x (%u)\n", symptr, symptr);
    printf("  NumberOfSymbols      = %u\n", nsym);
    printf("  SizeOfOptionalHeader = %u\n", optsz);
    printf("  Characteristics      = 0x%04x\n", chars);

    if (BOF_COFF_HDR_SIZE + (size_t)nsec * BOF_SEC_HDR_SIZE > n) {
        printf("[-] 节表超出文件范围\n");
        return 1;
    }

    printf("\n=== 节表 (%u 个 x 40 字节) ===\n", nsec);
    printf("  %-3s %-14s %8s %8s %8s %8s %6s  %s\n",
           "idx", "name", "VSize", "RawSize", "RawPtr", "RelPtr", "NRel", "特征");
    {
        unsigned int strtab = (nsym && symptr + (size_t)nsym * BOF_SYM_SIZE <= n)
                            ? symptr + nsym * BOF_SYM_SIZE : 0;
        for (i = 0; i < nsec; i++) {
            const unsigned char *p = b + BOF_COFF_HDR_SIZE + i * BOF_SEC_HDR_SIZE;
            char nm[20];
            char fl[128];
            unsigned int k = 0;

            /* 节名可能是 "/<十进制偏移>" 指向字符串表 (GCC 的长节名) */
            if (p[0] == '/' && p[1] >= '0' && p[1] <= '9' && strtab) {
                unsigned int off = 0, q, j = 1;
                while (j < 8 && p[j] >= '0' && p[j] <= '9') {
                    off = off * 10u + (unsigned int)(p[j] - '0');
                    j++;
                }
                q = strtab + off;
                if (q < n) {
                    while (q + k < n && b[q + k] && k < sizeof(nm) - 1) {
                        nm[k] = (char)b[q + k];
                        k++;
                    }
                }
            } else {
                while (k < 8 && p[k]) { nm[k] = (char)p[k]; k++; }
            }
            nm[k] = 0;

            sec_flags(r32(p + 36), fl, sizeof(fl));
            printf("  %-3u %-14s %8u %8u %8u %8u %6u  %s\n",
                   i + 1, nm, r32(p + 8), r32(p + 16), r32(p + 20),
                   r32(p + 24), r16(p + 32), fl);
            total_rel += r16(p + 32);
        }
    }

    /* ---- 符号表 ---- */
    printf("\n=== 符号表 (共 %u 项, 显示前 20 项) ===\n", nsym);
    if (nsym && symptr + (size_t)nsym * BOF_SYM_SIZE <= n) {
        strtab = symptr + nsym * BOF_SYM_SIZE;
        printf("  %-4s %-8s %6s %6s %6s %6s  %s\n",
               "idx", "value", "secnum", "sclass", "naux", "type", "name");
        for (i = 0; i < nsym && i < 20; ) {
            const unsigned char *p = b + symptr + i * BOF_SYM_SIZE;
            char nm[256];
            unsigned int j = 0;
            nm[0] = 0;
            if (p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0) {
                unsigned int off = r32(p + 4);
                unsigned int q = strtab + off;
                if (off && q < n) {
                    while (q + j < n && b[q + j] && j < sizeof(nm) - 1) {
                        nm[j] = (char)b[q + j];
                        j++;
                    }
                    nm[j] = 0;
                }
            } else {
                while (j < 8 && p[j]) { nm[j] = (char)p[j]; j++; }
                nm[j] = 0;
            }
            printf("  %-4u 0x%06x %6d %6u %6u %6u  %s\n",
                   i, r32(p + 8), (short)r16(p + 12), p[16], p[17], r16(p + 14), nm);
            i += 1u + (unsigned int)p[17];
        }
    } else {
        printf("  (无符号表)\n");
    }

    /* ---- 重定位统计 ---- */
    printf("\n=== 重定位统计 (共 %u 项) ===\n", total_rel);
    {
        unsigned int cnt[32];
        unsigned int unknown = 0;
        memset(cnt, 0, sizeof(cnt));
        for (i = 0; i < nsec; i++) {
            const unsigned char *p = b + BOF_COFF_HDR_SIZE + i * BOF_SEC_HDR_SIZE;
            unsigned int nr  = r16(p + 32);
            unsigned int rp  = r32(p + 24);
            for (r = 0; r < nr; r++) {
                unsigned int t;
                if (rp + (size_t)(r + 1) * BOF_RELOC_SIZE > n) break;
                t = r16(b + rp + r * BOF_RELOC_SIZE + 8);
                if (t < 32) cnt[t]++;
                else unknown++;
            }
        }
        for (i = 0; i < 32; i++) {
            if (cnt[i]) {
                const char *nm = "";
                switch (i) {
                case 1: nm = "IMAGE_REL_AMD64_ADDR64";   break;
                case 2: nm = "IMAGE_REL_AMD64_ADDR32";   break;
                case 3: nm = "IMAGE_REL_AMD64_ADDR32NB"; break;
                case 4: nm = "IMAGE_REL_AMD64_REL32";    break;
                case 5: nm = "IMAGE_REL_AMD64_REL32_1";  break;
                case 6: nm = "IMAGE_REL_AMD64_REL32_2";  break;
                case 7: nm = "IMAGE_REL_AMD64_REL32_3";  break;
                case 8: nm = "IMAGE_REL_AMD64_REL32_4";  break;
                case 9: nm = "IMAGE_REL_AMD64_REL32_5";  break;
                default: nm = "(其他)"; break;
                }
                printf("  type 0x%02x  %-26s x%u\n", i, nm, cnt[i]);
            }
        }
        if (unknown) printf("  type >=32                     x%u\n", unknown);
    }
    return 0;
}

/* ------------------------------------------------------------- probe */

static int cmd_probe(const unsigned char *b, unsigned int n, const char *label)
{
    unsigned int nsec = 0, nrel = 0;
    char entry[64];
    int  rc;

    rc = bof_probe(b, n, &nsec, &nrel, entry, sizeof(entry));
    printf("  %-30s sec=%-3u reloc=%-4u entry=%-5s rc=%d %s\n",
           label, nsec, nrel, entry[0] ? entry : "-", rc,
           rc == BOF_OK ? "OK" :
           rc == BOF_ERR_MACHINE ? "非AMD64" :
           rc == BOF_ERR_COFF ? "COFF结构错误" :
           rc == BOF_ERR_SYMBOL ? "外部符号未解析" :
           rc == BOF_ERR_RELOC ? "不支持的重定位" :
           rc == BOF_ERR_NOMEM ? "内存不足" : "其他");
    return rc;
}

/* --------------------------------------------------------------- run */
/* 参数按 BOF 约定打包: 每个字符串 = [4B 大端长度][UTF-8 数据]。
 * 大端是原版 bof_pack 的实际行为 (见 kits/beacon/bof_api.c 顶部证据链)。 */

static unsigned int pack_u32be(unsigned char *d, unsigned int v)
{
    d[0] = (unsigned char)((v >> 24) & 0xFF);
    d[1] = (unsigned char)((v >> 16) & 0xFF);
    d[2] = (unsigned char)((v >> 8) & 0xFF);
    d[3] = (unsigned char)(v & 0xFF);
    return 4;
}

static int cmd_run(const char *path, char **argv, int argc)
{
    unsigned char *coff;
    unsigned char *args;
    char          *out;
    unsigned int   cofflen = 0, argslen = 0, outlen = 0;
    unsigned int   cap, off = 0;
    int            i, rc;

    coff = read_file(path, &cofflen);
    if (!coff) { printf("[-] 无法读取 %s\n", path); return 1; }

    /* 参数块: 每个 argv 一个长度前缀字符串 + 末尾一个裸 int (演示 BeaconDataInt) */
    cap = 4096;
    for (i = 3; i < argc; i++) cap += (unsigned int)strlen(argv[i]) + 16;
    args = (unsigned char *)malloc(cap);
    out  = (char *)malloc(1u << 20);
    if (!args || !out) { printf("[-] 内存不足\n"); free(coff); free(args); free(out); return 1; }

    for (i = 3; i < argc; i++) {
        unsigned int L = (unsigned int)strlen(argv[i]);
        if (off + 4u + L + 8u > cap) break;
        off += pack_u32be(args + off, L);
        memcpy(args + off, argv[i], L);
        off += L;
        printf("[*] 打包参数 %d: \"%s\" (%u 字节)\n", i - 2, argv[i], L);
    }
    /* 追加一个整数参数: 参数个数 */
    {
        unsigned int v = (unsigned int)(argc - 3);
        args[off++] = (unsigned char)((v >> 24) & 0xFF);
        args[off++] = (unsigned char)((v >> 16) & 0xFF);
        args[off++] = (unsigned char)((v >> 8) & 0xFF);
        args[off++] = (unsigned char)(v & 0xFF);
    }
    argslen = off;
    printf("[*] 参数块共 %u 字节\n", argslen);

    printf("[*] 调用 bof_execute ...\n");
    rc = bof_execute(coff, cofflen, args, argslen, out, 1u << 20, &outlen);

    printf("\n=== BOF 执行返回 rc=%d, 输出 %u 字节 ===\n", rc, outlen);
    if (outlen) {
        fwrite(out, 1, outlen, stdout);
        if (out[outlen - 1] != '\n') printf("\n");
    } else {
        printf("(无输出)\n");
    }

    free(coff); free(args); free(out);

    if (rc != BOF_OK) {
        const char *why = "未知错误";
        switch (rc) {
        case BOF_ERR_ARG:     why = "入参非法";            break;
        case BOF_ERR_COFF:    why = "COFF 结构错误";        break;
        case BOF_ERR_MACHINE: why = "非 AMD64 目标文件";    break;
        case BOF_ERR_NOMEM:   why = "虚拟内存分配失败";      break;
        case BOF_ERR_SYMBOL:  why = "外部符号无法解析";      break;
        case BOF_ERR_RELOC:   why = "不支持的重定位类型";    break;
        case BOF_ERR_ENTRY:   why = "未找到入口符号 go/_go"; break;
        case BOF_ERR_CRASH:   why = "执行期间触发硬件异常";  break;
        default: break;
        }
        printf("[-] 失败原因: %s\n", why);
        return 1;
    }
    return 0;
}

/* -------------------------------------------------------------- scan */

static int  g_scan_ok, g_scan_bad;
static int  g_scan_why[10];

static void scan_one(const char *path, const char *name)
{
    unsigned char *b;
    unsigned int   n = 0;
    unsigned int   nsec = 0, nrel = 0;
    char           entry[64];
    int            rc;

    b = read_file(path, &n);
    if (!b) { printf("  [!] 读取失败: %s\n", name); g_scan_bad++; return; }

    rc = bof_probe(b, n, &nsec, &nrel, entry, sizeof(entry));
    if (rc == BOF_OK) {
        g_scan_ok++;
        printf("  [OK]   %-30s sec=%-2u reloc=%-4u entry=%s\n",
               name, nsec, nrel, entry[0] ? entry : "(无 go)");
    } else {
        g_scan_bad++;
        if (rc >= -9 && rc <= 0) g_scan_why[-rc]++;
        printf("  [FAIL] %-30s rc=%d %s\n", name, rc,
               rc == BOF_ERR_MACHINE ? "(非 AMD64)" :
               rc == BOF_ERR_COFF    ? "(结构错误)" :
               rc == BOF_ERR_SYMBOL  ? "(外部符号未解析)" :
               rc == BOF_ERR_RELOC   ? "(重定位类型不支持)" : "");
    }
    free(b);
}

static int cmd_scan(int argc, char **argv)
{
    int i;
    memset(g_scan_why, 0, sizeof(g_scan_why));
    bof_set_diag(on_diag);

    for (i = 2; i < argc; i++) {
        DWORD attr = GetFileAttributesA(argv[i]);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            /* 当作目录再试一次 */
            char pat[MAX_PATH + 8];
            WIN32_FIND_DATAA fd;
            HANDLE h;
            snprintf(pat, sizeof(pat), "%s\\*.o", argv[i]);
            h = FindFirstFileA(pat, &fd);
            if (h == INVALID_HANDLE_VALUE) {
                printf("[-] 路径不存在: %s\n", argv[i]);
                continue;
            }
            printf("\n=== 扫描目录 %s ===\n", argv[i]);
            do {
                char full[MAX_PATH * 2];
                snprintf(full, sizeof(full), "%s\\%s", argv[i], fd.cFileName);
                scan_one(full, fd.cFileName);
            } while (FindNextFileA(h, &fd));
            FindClose(h);
            continue;
        }
        if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            char pat[MAX_PATH + 8];
            WIN32_FIND_DATAA fd;
            HANDLE h;
            snprintf(pat, sizeof(pat), "%s\\*.o", argv[i]);
            h = FindFirstFileA(pat, &fd);
            if (h == INVALID_HANDLE_VALUE) { printf("[-] 目录内无 .o: %s\n", argv[i]); continue; }
            printf("\n=== 扫描目录 %s ===\n", argv[i]);
            do {
                char full[MAX_PATH * 2];
                snprintf(full, sizeof(full), "%s\\%s", argv[i], fd.cFileName);
                scan_one(full, fd.cFileName);
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        } else {
            printf("\n=== 单文件 %s ===\n", argv[i]);
            scan_one(argv[i], argv[i]);
        }
    }

    printf("\n=== 汇总: 可解析 %d 个 / 失败 %d 个 ===\n", g_scan_ok, g_scan_bad);
    if (g_scan_bad) {
        printf("失败原因分类:\n");
        printf("  非AMD64        : %d\n", g_scan_why[-BOF_ERR_MACHINE]);
        printf("  COFF结构错误   : %d\n", g_scan_why[-BOF_ERR_COFF]);
        printf("  外部符号未解析 : %d\n", g_scan_why[-BOF_ERR_SYMBOL]);
        printf("  重定位不支持   : %d\n", g_scan_why[-BOF_ERR_RELOC]);
        printf("  内存不足       : %d\n", g_scan_why[-BOF_ERR_NOMEM]);
    }
    return g_scan_bad ? 1 : 0;
}

/* ============================================================== main */

static void usage(void)
{
    printf("用法:\n");
    printf("  bof_test.exe dump  <file.o>            打印 COFF 结构\n");
    printf("  bof_test.exe probe <file.o>            只解析不执行\n");
    printf("  bof_test.exe run   <file.o> [arg ...]  加载并执行\n");
    printf("  bof_test.exe scan  <dir|file> ...      批量可解析性统计\n");
}

int main(int argc, char **argv)
{
    char **u;

    console_utf8();

    u = argv_utf8(&argc);
    if (u) argv = u;

    if (argc < 3) { usage(); return 2; }

    if (strcmp(argv[1], "dump") == 0) {
        unsigned char *b;
        unsigned int   n = 0;
        int rc;
        b = read_file(argv[2], &n);
        if (!b) { printf("[-] 无法读取 %s\n", argv[2]); return 1; }
        printf("文件: %s (%u 字节)\n\n", argv[2], n);
        rc = cmd_dump(b, n);
        free(b);
        return rc;
    }

    if (strcmp(argv[1], "probe") == 0) {
        unsigned char *b;
        unsigned int   n = 0;
        int rc;
        b = read_file(argv[2], &n);
        if (!b) { printf("[-] 无法读取 %s\n", argv[2]); return 1; }
        printf("文件: %s (%u 字节)\n", argv[2], n);
        bof_set_diag(on_diag);
        rc = cmd_probe(b, n, argv[2]);
        free(b);
        return rc == BOF_OK ? 0 : 1;
    }

    if (strcmp(argv[1], "run") == 0) {
        bof_set_diag(on_diag);
        return cmd_run(argv[2], argv, argc);
    }

    if (strcmp(argv[1], "scan") == 0) {
        return cmd_scan(argc, argv);
    }

    usage();
    return 2;
}
